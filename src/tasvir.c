#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#include "tasvir.h"

typedef void (*tasvir_area_desc_cb_fnptr)(tasvir_area_desc *);
static tasvir_tls_state ttls; /* tasvir thread-local state */

#define TASVIR_LOG(...)                                                                     \
    {                                                                                       \
        fprintf(stderr, "%14lu %-22.22s ", ttls.local ? ttls.local->time_us : 0, __func__); \
        fprintf(stderr, __VA_ARGS__);                                                       \
    }

#define TASVIR_MIN(x, y) (x < y ? x : y)

#define TASVIR_ALIGN_ARG(x) TASVIR_ALIGNX(x, sizeof(tasvir_arg_promo_t))

/* function prototypes */

static inline int tasvir_attach_helper(tasvir_area_desc *, tasvir_node *);
static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type);
static inline void tasvir_init_finish(tasvir_thread *);

/* rpc helpers */

#define R &((uint8_t *)v)[0]
#define X(i) &((uint8_t *)v)[o[i]]
static void rpc_tasvir_attach_helper(void *v, ptrdiff_t *o) {
    *(int *)R = tasvir_attach_helper(*(tasvir_area_desc **)X(0), *(tasvir_node **)X(1));
}

static void rpc_tasvir_delete(void *v, ptrdiff_t *o) { *(int *)R = tasvir_delete(*(tasvir_area_desc **)X(0)); }

static void rpc_tasvir_init_thread(void *v, ptrdiff_t *o) {
    *(tasvir_thread **)R = tasvir_init_thread(*(pid_t *)X(0), *(uint16_t *)X(1), *(uint8_t *)X(2));
}

static void rpc_tasvir_init_finish(void *v, ptrdiff_t *o) { tasvir_init_finish(*(tasvir_thread **)X(0)); }

static void rpc_tasvir_new(void *v, ptrdiff_t *o) {
    *(tasvir_area_desc **)R = tasvir_new(*(tasvir_area_desc *)X(0), *(size_t *)X(1));
}

static void rpc_tasvir_set_owner(void *v, ptrdiff_t *o) {
    tasvir_set_owner(*(tasvir_area_desc **)X(0), *(tasvir_thread **)X(1));
}
#undef R
#undef X

/* utils */

static inline void tasvir_hexdump(void *addr, size_t len) {
    uint8_t *b = (uint8_t *)addr;
    size_t i;
    for (i = 0; i < len; i += 4) {
        if (i && i % 32 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02X%02X%02X%02X ", b[i], b[i + 1], b[i + 2], b[i + 3]);
    }
    fprintf(stderr, "\n");
}

static inline int tasvir_barrier_wait(atomic_uint *count, int64_t timeout_us) {
    unsigned int val = atomic_fetch_sub(count, 1) - 1;
    while (val > 0) {
        if (timeout_us-- > 0) {
            rte_delay_us_block(1);
        } else {
            if (atomic_compare_exchange_weak(count, &val, val + 1)) {
                return -1;
            }
        }
        val = atomic_load(count);
    }
    return 0;
}

static inline uint64_t tasvir_gettime_us() { return 1E6 * rte_rdtsc() / ttls.local->tsc_hz; }

static inline bool tasvir_is_owner(tasvir_area_desc *d) {
    if (!d) { /* assuming called on root's pd */
        return ttls.is_root;
    } else if (!d->pd) { /* root area */
        return ttls.is_root;
    } else if (!ttls.thread) { /* preboot: node area, only daemon should ever reach here */
        assert(ttls.is_daemon);
        return ttls.is_daemon;
    } else if (!d->owner) { /* assume ownership if owner is NULL */
        return true;
    } else {
        return d->owner == ttls.thread;
    }
}

static inline bool tasvir_tid_match(tasvir_tid *id, tasvir_tid_type t) {
    switch (t) {
    case TASVIR_TID_BROADCAST:
        return memcmp(id, &ttls.any_dst_id, sizeof(tasvir_tid)) == 0;
    case TASVIR_TID_UPDATE:
        return memcmp(id, &ttls.update_dst_id, sizeof(tasvir_tid)) == 0;
    case TASVIR_TID_LOCAL:
        return memcmp(&id->nid, ttls.node ? &ttls.node->id : &ttls.any_src_id.nid, sizeof(tasvir_nid)) == 0;
    case TASVIR_TID_DEFAULT:
        return 1;
    default:
        return 0;
    }
}

static inline bool tasvir_is_thread_local(tasvir_thread *i) { return tasvir_tid_match(&i->id, TASVIR_TID_LOCAL); }

static inline void tasvir_tid2str(tasvir_tid *id, size_t buf_size, char *buf) {
    ether_format_addr(buf, buf_size, &id->nid.mac_addr);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), ":%d", id->idx);
}

static inline void tasvir_print_msg_rpc_info(tasvir_msg_rpc *msg, bool inbound) {
    tasvir_str src_str, dst_str;
    tasvir_tid2str(&msg->h.src_id, sizeof(src_str), src_str);
    tasvir_tid2str(&msg->h.dst_id, sizeof(dst_str), dst_str);
    TASVIR_LOG("%s %s->%s id=%d type=%s desc=%s fid=%d\n", inbound ? "incoming" : "outgoing", src_str, dst_str,
               msg->h.id, msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST ? "request" : "response",
               msg->d ? msg->d->name : "ROOT", msg->fid);
    // tasvir_hexdump(&msg->h.eh, msg->h.mbuf.data_len);
}

static inline void tasvir_change_vaddr(void *base1, void *base2, size_t len, bool swap) {
    void *ret;
    ptrdiff_t base1_rel = (uint8_t *)(swap ? base2 : base1) - (uint8_t *)TASVIR_ADDR_BASE;
    ptrdiff_t base2_rel = (uint8_t *)(swap ? base1 : base2) - (uint8_t *)TASVIR_ADDR_BASE;
    ret = mmap(base1, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttls.fd, base1_rel);
    if (ret != base1) {
        TASVIR_LOG("mmap for working area failed (request=%p return=%p)\n", ret, base1);
        abort();
    }
    ret = mmap(base2, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttls.fd, base2_rel);
    if (ret != base2) {
        TASVIR_LOG("mmap for scratch area failed (request=%p return=%p)\n", ret, base1);
        abort();
    }
}

static inline void tasvir_mov32_stream(void *dst, const void *src) {
    __m256i m = _mm256_stream_load_si256((const __m256i *)src);
    _mm256_stream_si256((__m256i *)dst, m);
}

static inline void tasvir_mov64_stream(void *dst, const void *src) {
    tasvir_mov32_stream(dst, src);
    tasvir_mov32_stream((uint8_t *)dst + 32, (uint8_t *)src + 32);
}

static inline void tasvir_mov32blocks_stream(void *dst, const void *src, size_t len) {
    /* TASVIR_LOG("%p->%p %lu\n", src, dst, len); */
    while (len > 0) {
        tasvir_mov32_stream(dst, src);
        /* rte_mov32(dst, src); */
        len -= 32;
        dst = (uint8_t *)dst + 32;
        src = (uint8_t *)src + 32;
    }
}

static inline void tasvir_memset_stream(void *dst, char c, size_t len) {
    uint8_t *ptr = dst;
    while ((uintptr_t)ptr & 31UL) {
        *ptr = c;
        ptr++;
    }
    __m256i m = _mm256_set1_epi8(c);
    while (len >= 32) {
        _mm256_stream_si256((__m256i *)ptr, m);
        ptr += 32;
        len -= 32;
    }
    while (len-- > 0)
        *ptr++ = c;
}

/* initializtion */

static inline void tasvir_init_rpc() {
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_init_thread,
        .name = "tasvir_init_thread",
        .fid = 1,
        .argc = 3,
        .ret_len = sizeof(tasvir_thread *),
        .arg_lens = {sizeof(pid_t), sizeof(uint16_t), sizeof(uint8_t)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){.fnptr = &rpc_tasvir_new,
                                          .name = "tasvir_new",
                                          .fid = 2,
                                          .argc = 2,
                                          .ret_len = sizeof(tasvir_area_desc *),
                                          .arg_lens = {sizeof(tasvir_area_desc), sizeof(size_t)}});
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_delete,
        .name = "tasvir_delete",
        .fid = 3,
        .argc = 1,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_init_finish,
        .name = "tasvir_init_finish",
        .fid = 4,
        .argc = 1,
        .ret_len = 0,
        .arg_lens = {sizeof(tasvir_thread *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_set_owner,
        .name = "tasvir_set_owner",
        .fid = 5,
        .argc = 2,
        .ret_len = 0,
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_thread *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_attach_helper,
        .name = "tasvir_attach_helper",
        .fid = 6,
        .argc = 2,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_node *)},
    });
}

static inline int tasvir_init_dpdk(uint16_t core, char *pciaddr) {
    int argc = 0, retval;
    char *argv[64];
    char core_str[32], mem_str[32], base_virtaddr[32];
    snprintf(core_str, sizeof(core_str), "%d", core);
    snprintf(mem_str, sizeof(mem_str), "512,512");
    snprintf(base_virtaddr, sizeof(base_virtaddr), "%p", TASVIR_DPDK_ADDR_BASE);
    argv[argc++] = "tasvir";
    argv[argc++] = "--base-virtaddr";
    argv[argc++] = base_virtaddr;
    argv[argc++] = "-l";
    argv[argc++] = core_str;
    argv[argc++] = "-n";
    argv[argc++] = "4";
    argv[argc++] = "--file-prefix";
    argv[argc++] = "tasvir";
    argv[argc++] = "--log-level";
    argv[argc++] = "0";
    argv[argc++] = "--socket-mem";
    argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
    argv[argc++] = ttls.is_daemon ? "primary" : "secondary";
    if (pciaddr) {
        argv[argc++] = "--pci-whitelist";
        argv[argc++] = pciaddr;
    }
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        TASVIR_LOG("rte_eal_init failed\n");
        return -1;
    }
    return 0;
}

static int tasvir_init_port(char *pciaddr) {
    if (!ttls.is_daemon || !pciaddr)
        return 0;

    int nb_ports = rte_eth_dev_count();
    if (nb_ports != 1) {
        TASVIR_LOG("rte_eth_dev_count() != 1\n");
        return -1;
    }
    ttls.local->dstate.port_id = 0;
    rte_eth_macaddr_get(ttls.local->dstate.port_id, &ttls.local->dstate.mac_addr);
    ether_addr_copy(&ttls.local->dstate.mac_addr, &ttls.any_src_id.nid.mac_addr);

    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf *rx_conf;
    struct rte_eth_txconf *tx_conf;
    struct rte_eth_link link;
    uint64_t end_time_us;
    int retval;

    /* prepare configs */
    memset(&port_conf, 0, sizeof(port_conf));
    rte_eth_dev_info_get(ttls.local->dstate.port_id, &dev_info);
    rx_conf = &dev_info.default_rxconf;
    tx_conf = &dev_info.default_txconf;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    port_conf.rxmode.split_hdr_size = 0;
    port_conf.rxmode.header_split = 0;
    port_conf.rxmode.hw_ip_checksum = 0;
    port_conf.rxmode.hw_vlan_filter = 0;
    port_conf.rxmode.jumbo_frame = 0;
    port_conf.rxmode.hw_strip_crc = 1;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf.intr_conf.lsc = 0;

    retval = rte_eth_dev_configure(ttls.local->dstate.port_id, 1, 1, &port_conf);
    if (retval < 0) {
        TASVIR_LOG("Cannot configure device: err=%d, port=%d\n", retval, ttls.local->dstate.port_id);
        return -1;
    }

    retval = rte_eth_rx_queue_setup(ttls.local->dstate.port_id, 0, 4096,
                                    rte_eth_dev_socket_id(ttls.local->dstate.port_id), rx_conf, ttls.local->mp);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_rx_queue_setup:err=%d, port=%u\n", retval, (unsigned)ttls.local->dstate.port_id);
        return -1;
    }

    retval = rte_eth_tx_queue_setup(ttls.local->dstate.port_id, 0, 4096,
                                    rte_eth_dev_socket_id(ttls.local->dstate.port_id), tx_conf);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_tx_queue_setup:err=%d, port=%u\n", retval, (unsigned)ttls.local->dstate.port_id);
        return -1;
    }

    retval = rte_eth_dev_start(ttls.local->dstate.port_id);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_dev_start: err=%d, port=%u\n", retval, ttls.local->dstate.port_id);
        return -1;
    }

    retval = rte_eth_dev_set_link_up(ttls.local->dstate.port_id);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_dev_set_link_up: err=%d, port=%u\n", retval, ttls.local->dstate.port_id);
        return -1;
    }

    end_time_us = tasvir_gettime_us() + 10 * 1000 * 1000;
    do {
        rte_eth_link_get(ttls.local->dstate.port_id, &link);
    } while (tasvir_gettime_us() > end_time_us || link.link_status != ETH_LINK_UP);

    if (link.link_status != ETH_LINK_UP) {
        TASVIR_LOG("rte_eth_link_get_nowait: link is down port=%u\n", ttls.local->dstate.port_id);
        return -1;
    }
    rte_eth_promiscuous_enable(ttls.local->dstate.port_id);

    tasvir_str buf;
    ether_format_addr(buf, sizeof(buf), &ttls.local->dstate.mac_addr);
    TASVIR_LOG("port=%d mac=%s\n", ttls.local->dstate.port_id, buf);

    return 0;
}

static int tasvir_init_local() {
    void *base;
    int shm_oflag = ttls.is_daemon ? O_CREAT | O_EXCL | O_RDWR : O_RDWR;
    mode_t shm_mode = ttls.is_daemon ? S_IRUSR | S_IWUSR : 0;
    ptrdiff_t size_whole = (uint8_t *)TASVIR_ADDR_END - (uint8_t *)TASVIR_ADDR_BASE;

    ttls.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttls.fd == -1)
        return -1;
    if (ftruncate(ttls.fd, size_whole)) {
        TASVIR_LOG("ftruncate failed (%s)\n", strerror(errno));
        return -1;
    }
    base = mmap(TASVIR_ADDR_BASE, size_whole, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttls.fd, 0);
    if (base != TASVIR_ADDR_BASE) {
        TASVIR_LOG("mmap failed\n");
        return -1;
    }

    ttls.local = TASVIR_ADDR_LOCAL;

    if (ttls.is_daemon) {
        memset(ttls.local, 0, sizeof(tasvir_local));
        /* boot mutex */
        pthread_mutexattr_setpshared(&ttls.local->mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ttls.local->mutex_boot, &ttls.local->mutex_attr);

        /* mempool */
        ttls.local->mp =
            rte_pktmbuf_pool_create("mempool", 200 * 1024, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!ttls.local->mp) {
            TASVIR_LOG("failed to create pkt mempool\n");
            return -1;
        }

        /* tx ring */
        ttls.local->ring_ext_tx =
            rte_ring_create("tasvir_ext_tx", TASVIR_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (ttls.local->ring_ext_tx == NULL) {
            TASVIR_LOG("failed to create external rings");
            return -1;
        }

        /* timing */
        ttls.local->tsc_hz = rte_get_tsc_hz();
    }

    return 0;
}

static int tasvir_init_root() {
    tasvir_area_desc *d_ret;
    ttls.root_desc = (tasvir_area_desc *)TASVIR_ADDR_ROOT_DESC;

    if (ttls.is_root) {
        d_ret = tasvir_new((tasvir_area_desc){.pd = NULL,
                                              .owner = NULL,
                                              .type = TASVIR_AREA_TYPE_CONTAINER,
                                              .name = "root",
                                              .len = TASVIR_SIZE_DATA - 2 * TASVIR_HUGEPAGE_SIZE,
                                              .stale_us = 50000},
                           TASVIR_HUGEPAGE_SIZE);
    } else {
        d_ret = tasvir_attach(NULL, "root", NULL);
    }

    if (d_ret == MAP_FAILED) {
        TASVIR_LOG("failed to create/attach to root area\n");
        return -1;
    } else if (d_ret != ttls.root_desc) {
        TASVIR_LOG("returned address doesn't match root_desc address\n")
        return -1;
    }

    return 0;
}

static int tasvir_init_node() {
    /* FIXME: assuming a clean boot */
    tasvir_str name = "node-";
    ether_format_addr(&name[strlen(name)], sizeof(name) - strlen(name), &ttls.local->dstate.mac_addr);

    if (ttls.is_daemon) {
        /* id and address */
        ttls.node_desc = tasvir_new((tasvir_area_desc){.pd = ttls.root_desc,
                                                       .owner = NULL,
                                                       .type = TASVIR_AREA_TYPE_NODE,
                                                       .name_static = *(tasvir_str_static *)name,
                                                       .len = sizeof(tasvir_node),
                                                       .stale_us = 50000},
                                    0);
        if (ttls.node_desc == MAP_FAILED) {
            TASVIR_LOG("failed to allocate node\n");
            return -1;
        }
        ttls.node = (tasvir_node *)ttls.node_desc->h->data;
        memset(ttls.node, 0, sizeof(tasvir_node));
        ether_addr_copy(&ttls.local->dstate.mac_addr, &ttls.node->id.mac_addr);
        ttls.node->heartbeat_us = TASVIR_HEARTBEAT_US;

        /* time */
        tasvir_log_write(ttls.node, sizeof(tasvir_node));
    } else {
        ttls.node_desc = tasvir_attach(ttls.root_desc, name, NULL);
        ttls.node = (tasvir_node *)ttls.node_desc->h->data;
        tasvir_local_tstate *daemon_tstate = &ttls.local->tstate[TASVIR_THREAD_DAEMON_IDX];

        /* daemon alive? */
        uint64_t time_us = tasvir_gettime_us();
        if (!ttls.node_desc->active) {
            TASVIR_LOG("daemon is inactive\n");
            return -1;
        } else if (time_us > daemon_tstate->update_us &&
                   time_us - daemon_tstate->update_us > ttls.node_desc->stale_us) {
            TASVIR_LOG("daemon has been stale for %lu us (> %lu), last activity %lu\n",
                       time_us - ttls.node_desc->h->update_us, ttls.node_desc->stale_us, ttls.node_desc->h->update_us);
            return -1;
        }
    }

    return 0;
}

static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type) {
    tasvir_thread *t = NULL;

    if (ttls.is_daemon) {
        uint16_t tid;
        /* find a free thread id */
        for (tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
            if (ttls.node->threads[tid].status != TASVIR_THREAD_STATUS_RUNNING &&
                ttls.node->threads[tid].status != TASVIR_THREAD_STATUS_BOOTING)
                break;
        }

        if (tid == TASVIR_NR_THREADS_LOCAL)
            return NULL;

        /* populate thread */
        t = &ttls.node->threads[tid];
        tasvir_log_write(t, sizeof(tasvir_thread));
        t->core = core;
        t->type = type;
        t->id.nid = ttls.node->id;
        t->id.idx = tid;
        t->id.pid = pid;
        t->status = TASVIR_THREAD_STATUS_BOOTING;

        tasvir_local_tstate *tstate = &ttls.local->tstate[tid];
        tasvir_str tmp;
        /* rings */
        sprintf(tmp, "tasvir_tx_%d", tid);
        tstate->ring_tx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        sprintf(tmp, "tasvir_rx_%d", tid);
        tstate->ring_rx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (tstate->ring_tx == NULL || tstate->ring_rx == NULL) {
            TASVIR_LOG("failed to create rings for tid %d", tid);
            return NULL;
        }
    } else {
        /* FIXME: deadlock on crash */
        pthread_mutex_lock(&ttls.local->mutex_boot);
        t = tasvir_rpc_sync(ttls.node_desc, 10 * 1000 * 1000, &rpc_tasvir_init_thread, pid, core, type);
        pthread_mutex_unlock(&ttls.local->mutex_boot);
    }

    TASVIR_LOG("addr=%p tid=%d core=%d pid=%d status=%d\n", (void *)t, t->id.idx, t->core, t->id.pid, t->status);
    return t;
}

static inline void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container *c = (tasvir_area_container *)d->h->data;
        for (size_t i = 0; i < c->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c->descs[i]);
    }
    if (d->owner == t)
        tasvir_set_owner(d, NULL);
}

static inline void tasvir_kill_thread(tasvir_thread *t) {
    assert(ttls.is_daemon && tasvir_is_thread_local(t));
    tasvir_local_tstate *tstate = &ttls.local->tstate[t->id.idx];
    TASVIR_LOG("thread=%d idle_time=%zd remaining_threads=%lu\n", t->id.idx, ttls.local->time_us - tstate->update_us,
               ttls.node->nr_threads - 1);
    tstate->sync = false;
    tstate->update_us = 0;

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttls.root_desc);

    /* kill by pid */
    /* kill(t->id.pid, SIGKILL); */

    ttls.node->nr_threads--;
    tasvir_log_write(&ttls.node->nr_threads, sizeof(ttls.node->nr_threads));
    t->status = TASVIR_THREAD_STATUS_DEAD;
    tasvir_log_write(&t->status, sizeof(t->status));

    rte_ring_free(ttls.local->tstate[t->id.idx].ring_rx);
    rte_ring_free(ttls.local->tstate[t->id.idx].ring_tx);
}

static inline void tasvir_init_finish(tasvir_thread *t) {
    if (t->status != TASVIR_THREAD_STATUS_BOOTING) {
        TASVIR_LOG("called from a thread that is not in the BOOTING state (status=%d)\n", t->status);
        abort();
    }
    if (ttls.is_daemon) {
        tasvir_log_write(&t->status, sizeof(t->status));
        tasvir_log_write(&ttls.node->nr_threads, sizeof(ttls.node->nr_threads));
        t->status = TASVIR_THREAD_STATUS_RUNNING;
        ttls.node->nr_threads++;

        /* backfill area owners */
        if (t == ttls.thread) {
            tasvir_log_write(&ttls.node_desc->owner, sizeof(tasvir_thread *));
            ttls.node_desc->owner = ttls.thread;
            if (ttls.is_root) {
                tasvir_log_write(&ttls.root_desc->owner, sizeof(tasvir_thread *));
                ttls.root_desc->owner = ttls.thread;
            }
        }
    } else {
        tasvir_rpc_sync(ttls.node_desc, 10 * 1000 * 1000, &rpc_tasvir_init_finish, t);
    }

    TASVIR_LOG("tid=%d core=%d pid=%d\n", t->id.idx, t->core, t->id.pid);
}

tasvir_area_desc *tasvir_init(uint8_t type, uint16_t core, char *pciaddr) {
    _Static_assert(sizeof(tasvir_local) <= TASVIR_SIZE_LOCAL, "TASVIR_SIZE_LOCAL smaller than sizeof(tasvir_local)");
    assert(!ttls.node && !ttls.thread);

    memset(&ttls, 0, sizeof(tasvir_tls_state));
    ttls.is_daemon = type == TASVIR_THREAD_TYPE_DAEMON || type == TASVIR_THREAD_TYPE_ROOT;
    ttls.is_root = type == TASVIR_THREAD_TYPE_ROOT;

    ttls.update_dst_id.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x00}}};
    ttls.update_dst_id.idx = -1;
    ttls.update_dst_id.pid = -1;
    ttls.any_dst_id.nid = (tasvir_nid){.mac_addr = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}};
    ttls.any_dst_id.idx = -1;
    ttls.any_dst_id.pid = -1;
    ttls.any_src_id = ttls.any_dst_id;

    tasvir_init_rpc();

    TASVIR_LOG("init dpdk\n");
    if (tasvir_init_dpdk(core, pciaddr)) {
        TASVIR_LOG("tasvir_init_dpdk failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init local\n");
    if (tasvir_init_local()) {
        TASVIR_LOG("tasvir_init_local failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init port\n");
    if (tasvir_init_port(pciaddr)) {
        TASVIR_LOG("tasvir_init_port failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init root\n");
    if (tasvir_init_root()) {
        TASVIR_LOG("tasvir_init_root failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init node\n");
    if (tasvir_init_node()) {
        TASVIR_LOG("tasvir_init_node failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init thread\n");
    ttls.thread = tasvir_init_thread(getpid(), core, type);
    if (!ttls.thread) {
        TASVIR_LOG("tasvir_init_thread failed\n");
        return MAP_FAILED;
    }

    TASVIR_LOG("init finish\n");
    tasvir_init_finish(ttls.thread);

    return ttls.root_desc;
}

/* area management */

tasvir_area_desc *tasvir_new(tasvir_area_desc desc, size_t container_len) {
    desc.active = true;
    if (!desc.owner && desc.type != TASVIR_AREA_TYPE_NODE)
        desc.owner = ttls.thread;

    tasvir_area_desc *d = NULL;
    tasvir_area_container *c = NULL;
    uint64_t time_us = tasvir_gettime_us();
    bool is_root_area = !desc.pd;
    bool is_desc_owner = tasvir_is_owner(desc.pd);
    bool is_owner = desc.type == TASVIR_AREA_TYPE_NODE ? !ttls.node : tasvir_is_owner(&desc);
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;

    size_t i;
    size_t size_metadata = sizeof(tasvir_area_header) + container_len;
    size_t size_data = desc.len;
    size_t size_loggable = TASVIR_ALIGN(size_metadata + (is_container ? 0 : size_data));
    size_t size_log = TASVIR_ALIGNX((size_loggable >> TASVIR_SHIFT_BYTE), 8 * sizeof(tasvir_log_t));
    desc.len = TASVIR_ALIGN(size_metadata + size_data) + TASVIR_NR_AREA_LOGS * size_log;

    assert(is_root_area || desc.pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(!is_root_area || is_container);
    assert(is_container || container_len == 0);

    /* initialize area descriptor */
    if (is_desc_owner) {
        void *h = NULL;
        if (is_root_area) {
            d = ttls.root_desc;
            h = TASVIR_ADDR_DATA;
        } else {
            c = (tasvir_area_container *)desc.pd->h->data;
            assert(sizeof(tasvir_area_container) + (c->nr_areas + 1) * sizeof(tasvir_area_desc) <= c->len);

            d = &c->descs[c->nr_areas];

            /* area exists */
            for (i = 0; i < c->nr_areas; i++) {
                if (strncmp(c->descs[i].name, desc.name, sizeof(tasvir_str)) == 0) {
                    return NULL;
                }
            }

            tasvir_log_write(&c->nr_areas, sizeof(c->nr_areas));
            if (c->nr_areas > 0) {
                h = (uint8_t *)c->descs[c->nr_areas - 1].h + c->descs[c->nr_areas - 1].len;
            } else {
                h = (uint8_t *)c->descs + c->len;
            }
            h = (void *)TASVIR_ALIGN((uintptr_t)h);
            if ((uint8_t *)h + desc.len > (uint8_t *)desc.pd->h + desc.pd->len) {
                TASVIR_LOG("out of space\n");
                return MAP_FAILED;
            }
            c->nr_areas++;
        }
        tasvir_log_write(d, sizeof(tasvir_area_desc));
        memcpy(d, &desc, sizeof(tasvir_area_desc));
        d->h = h;
        d->boot_us = time_us;
    } else {
        d = tasvir_rpc_sync(desc.pd, 10 * 1000 * 1000, &rpc_tasvir_new, desc, container_len);
        if (!d || !d->h) {
            return MAP_FAILED;
        }
    }

    if (is_owner) {
        tasvir_set_owner(d, ttls.thread);
        tasvir_log_write(d->h, sizeof(tasvir_area_header) + is_container * sizeof(tasvir_area_container));
        memset(d->h, 0, size_metadata);
        d->h->d = d;
        d->h->version = 0;
        d->h->update_us = time_us;
        d->h->nr_users = 1;
        d->h->users[0].node = ttls.node;
        d->h->users[0].version = 0;
        if (is_container) {
            c = (tasvir_area_container *)&d->h->data;
            c->nr_areas = 0;
            c->len = container_len;
        }
        for (i = 0; i < TASVIR_NR_AREA_LOGS; i++) {
            tasvir_area_log *log = &d->h->diff_log[i];
            log->version_start = 0;
            log->version_end = 0;
            log->ts_first_us = time_us;
            log->ts_last_us = 0;
            log->data = (tasvir_log_t *)((uint8_t *)d->h + d->len - (TASVIR_NR_AREA_LOGS - i) * size_log);
        }
    }

    TASVIR_LOG(
        "is_desc_owner=%d is_owner=%d d=%p pd=%p owner=%p type=%d name=%s len=%lu h=%p stale_us=%lu "
        "container_len=%lu boot_us=%lu\n",
        is_desc_owner, is_owner, (void *)d, (void *)d->pd, (void *)d->owner, d->type, d->name, d->len, (void *)d->h,
        d->stale_us, container_len, d->boot_us);

    return d;
}

int tasvir_delete(tasvir_area_desc *d) {
    assert(d->pd);
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);

    /* TODO: remove from d->pd */
    if (tasvir_is_owner(d->pd)) {
        d->active = false;
    } else {
        return *(int *)tasvir_rpc_sync(d->pd, 10 * 1000 * 1000, &rpc_tasvir_delete, d);
    }
    return 0;
}

tasvir_area_desc *tasvir_lookup(tasvir_area_desc *pd, char *name) {
    size_t i;
    tasvir_area_container *c;
    tasvir_area_desc *d = NULL;
    bool is_root_area = !pd;
    if (is_root_area) {
        d = ttls.root_desc;
    } else {
        if (!pd && pd->type != TASVIR_AREA_TYPE_CONTAINER) {
            TASVIR_LOG("parent descriptor is invalid\n");
            return MAP_FAILED;
        }
        c = (tasvir_area_container *)pd->h->data;
        if (sizeof(tasvir_area_container) + c->nr_areas * sizeof(tasvir_area_desc) > c->len) {
            TASVIR_LOG("invalid number of areas in %s: nr_areas=%lu container_len=%lu\n", pd->name, c->nr_areas,
                       c->len);
            return MAP_FAILED;
        }
        for (i = 0; i < c->nr_areas; i++) {
            if (strncmp(c->descs[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &c->descs[i];
                break;
            }
        }
    }

    if (d == NULL) {
        TASVIR_LOG("could not find area %s under %s\n", name, pd->name);
    }

    return d;
}

static inline int tasvir_attach_helper(tasvir_area_desc *d, tasvir_node *node) {
    size_t i;
    if (d->h) {
        for (i = 0; i < d->h->nr_users; i++) {
            if (d->h->users[i].node == ttls.node) {
                TASVIR_LOG("already subscribed to %s\n", d->name);
                return 0;
            }
        }
    }

    if (tasvir_is_owner(d)) {
        if (d->h->nr_users >= TASVIR_NR_NODES_AREA) {
            TASVIR_LOG("%s has reached max number of subscribers\n", d->name);
            return -1;
        }

        if (node) {
            d->h->users[d->h->nr_users].node = node;
            d->h->users[d->h->nr_users].version = 0;
            d->h->nr_users++;
        }
    } else {
        if (tasvir_rpc_sync(d, 10 * 1000 * 1000, &rpc_tasvir_attach_helper, d, node) != 0 || !d->h)
            return -1;
    }

    return 0;
}

tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, char *name, tasvir_node *node) {
    tasvir_area_desc *d = tasvir_lookup(pd, name);
    if (d == NULL)
        return MAP_FAILED;

    if (node == NULL)
        node = ttls.node;

    if (tasvir_attach_helper(d, node) == 0) {
        TASVIR_LOG("name=%s len=%lu h=%p\n", d->name, d->len, (void *)d->h);
        return d;
    } else {
        return MAP_FAILED;
    }
}

int tasvir_detach(tasvir_area_desc *d) {
    assert(d->pd);
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);

    /* FIXME: update subscriber's list */

    return 0;
}

void tasvir_set_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    size_t len;
    tasvir_thread *desc_owner = d->pd ? d->pd->owner : d->owner;
    bool is_new_owner = owner == ttls.thread;
    bool is_old_owner = d->owner == ttls.thread;
    bool is_desc_owner = desc_owner == ttls.thread;
    void *base = d->h;
    void *base_shadow = tasvir_data2shadow(base);

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container *c = (tasvir_area_container *)d->h->data;
        len = sizeof(tasvir_area_header) + c->len;
    } else {
        len = d->len;
    }

    if (is_desc_owner) {
        d->owner = owner;
        tasvir_log_write(&d->owner, sizeof(d->owner));
    }

    if (is_new_owner) {
        tasvir_change_vaddr(base, base_shadow, len, true);

        /* FIXME: change to async and wait for change to propagate */
        if (d->owner && !is_old_owner) {
            /* rpc to previous owner */
            tasvir_rpc_sync(d, 10 * 1000 * 1000, &rpc_tasvir_set_owner, d, owner);
        }

        if (desc_owner && !is_desc_owner) {
            /* rpc to desc owner */
            tasvir_rpc_sync(d->pd, 10 * 1000 * 1000, &rpc_tasvir_set_owner, d, owner);
        }
    } else if (is_old_owner) {
        /* restore the mappings of the old owner */
        tasvir_change_vaddr(base, base_shadow, len, false);
    }
}

/* rpc */

/* return 0 if message sent out */
static int tasvir_route_msg(tasvir_msg *msg, bool inbound) {
    /* destination broadcast is only meant for the root daemon */
    bool is_dst_any = tasvir_tid_match(&msg->dst_id, TASVIR_TID_BROADCAST);
    bool is_dst_update = tasvir_tid_match(&msg->dst_id, TASVIR_TID_UPDATE);
    bool is_dst_local = is_dst_any ? ttls.is_root || msg->type == TASVIR_MSG_TYPE_MEM
                                   : is_dst_update || tasvir_tid_match(&msg->dst_id, TASVIR_TID_LOCAL);
    bool is_mine = inbound && is_dst_local && ((is_dst_any && ttls.is_root) || (is_dst_update && ttls.is_daemon) ||
                                               !ttls.thread || msg->dst_id.idx == ttls.thread->id.idx);
    struct rte_ring *r;

    if (is_mine || (inbound && !ttls.is_daemon)) {
        /* no-op when message is ours or reached here by error */
        return -1;
    } else if (ttls.is_daemon) {
        uint16_t tid = is_dst_any ? TASVIR_THREAD_DAEMON_IDX : msg->dst_id.idx;
        r = is_dst_local ? ttls.local->tstate[tid].ring_rx : ttls.local->ring_ext_tx;
    } else {
        uint16_t tid = ttls.thread ? ttls.thread->id.idx : TASVIR_THREAD_DAEMON_IDX;
        r = ttls.local->tstate[tid].ring_tx;
    }

    if (rte_ring_sp_enqueue(r, msg) != 0) {
        TASVIR_LOG("rte_ring_sp_enqueue failed\n");
        rte_mempool_put(ttls.local->mp, (void *)msg);
        abort();
        return -1;
    }
    if (!ttls.is_root && msg->id > 1000) {
        tasvir_str src_str, dst_str;
        tasvir_tid2str(&msg->src_id, sizeof(src_str), src_str);
        tasvir_tid2str(&msg->dst_id, sizeof(dst_str), dst_str);
        TASVIR_LOG("%s %s->%s id=%d type=%s\n", inbound ? "incoming" : "outgoing", src_str, dst_str, msg->id,
                   msg->type == TASVIR_MSG_TYPE_RPC_REQUEST ? "request" : "response");

        TASVIR_LOG("%d %d %d\n", is_dst_any, is_dst_local, is_mine);
        abort();
    }

    return 0;
}

static tasvir_rpc_status *tasvir_vrpc_async(tasvir_area_desc *d, tasvir_fnptr fnptr, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *msg;
    tasvir_rpc_status *status;
    if (rte_mempool_get(ttls.local->mp, (void **)&msg)) {
        TASVIR_LOG("rte_mempool_get failed\n");
        return NULL;
    }

    tasvir_fn_info *fni;
    HASH_FIND(h_fnptr, ttls.ht_fnptr, &fnptr, sizeof(fnptr), fni);
    assert(fni);

    /* FIXME: using daemon id as src during boot to simplify impl */
    msg->h.src_id = ttls.thread ? ttls.thread->id : ttls.any_src_id;
    msg->h.dst_id = d && d->owner ? d->owner->id : ttls.any_dst_id;
    msg->h.id = ttls.nr_msgs++;
    msg->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    msg->h.time_us = d && d->h ? d->h->update_us : ttls.local->time_us;
    msg->d = d;
    msg->fid = fni->fid;

    for (i = 0; i < fni->argc; i++) {
        ptr = &msg->data[fni->arg_offsets[i]];
        switch (fni->arg_lens[i]) {
        case 8:
            *(uint64_t *)ptr = va_arg(argp, uint64_t);
            break;
        case 16:
            *(__uint128_t *)ptr = va_arg(argp, __uint128_t);
            break;
        case (sizeof(tasvir_str_static)):
            *(tasvir_str_static *)ptr = va_arg(argp, tasvir_str_static);
            break;
        case (sizeof(tasvir_area_desc)):
            *(tasvir_area_desc *)ptr = va_arg(argp, tasvir_area_desc);
            break;
        default:
            if (fni->arg_lens[i] <= sizeof(tasvir_arg_promo_t)) {
                *(tasvir_arg_promo_t *)ptr = va_arg(argp, int);
            } else {
                TASVIR_LOG("missing support for argument of len=%lu\n", fni->arg_lens[i]);
                abort();
            }
            break;
        }
    }
    msg->h.mbuf.pkt_len = msg->h.mbuf.data_len = TASVIR_ALIGN_ARG(ptr + fni->arg_lens[i - 1] - (uint8_t *)&msg->h.eh);

    tasvir_print_msg_rpc_info((tasvir_msg_rpc *)msg, false);
    if (tasvir_route_msg((tasvir_msg *)msg, false) != 0) {
        return NULL;
    }

    status = &ttls.status_l[msg->h.id];
    /* garbage collect a previous status */
    if (status->response)
        rte_mempool_put(ttls.local->mp, (void *)status->response);
    status->id = msg->h.id;
    status->status = TASVIR_RPC_STATUS_PENDING;
    status->response = NULL;
    status->cb = NULL;
    return status;
}

tasvir_rpc_status *tasvir_rpc_async(tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(d, fnptr, argp);
    va_end(argp);
    return status;
}

void *tasvir_rpc_sync(tasvir_area_desc *d, uint64_t timeout_us, tasvir_fnptr fnptr, ...) {
    uint64_t time_end = tasvir_gettime_us() + timeout_us;
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(d, fnptr, argp);
    va_end(argp);

    while (ttls.local->time_us < time_end && status->status == TASVIR_RPC_STATUS_PENDING) {
        tasvir_service();
    }

    if (status->status == TASVIR_RPC_STATUS_DONE) {
        /* FIXME: find a proper way to ensure state is visible */
        while (ttls.local->time_us < time_end &&
               (!status->response->d->h || status->response->d->h->update_us < status->response->h.time_us)) {
            tasvir_service();
        }
        tasvir_service();
    }

    if (status->status != TASVIR_RPC_STATUS_DONE)
        abort();

    /* FIXME: horrible error handling */
    assert(status->status != TASVIR_RPC_STATUS_DONE || status->response);
    return status->status == TASVIR_RPC_STATUS_DONE ? *(void **)status->response->data : NULL;
}

int tasvir_rpc_register(tasvir_fn_info *fni) {
    int i;
    ttls.fn_infos[ttls.nr_fns] = *fni;
    fni = &ttls.fn_infos[ttls.nr_fns];
    ptrdiff_t ptr = TASVIR_ALIGN_ARG(fni->ret_len);
    for (i = 0; i < fni->argc; i++) {
        fni->arg_offsets[i] = ptr;
        ptr += TASVIR_ALIGN_ARG(fni->arg_lens[i]);
    }
    HASH_ADD(h_fid, ttls.ht_fid, fid, sizeof(fni->fid), &ttls.fn_infos[ttls.nr_fns]);
    HASH_ADD(h_fnptr, ttls.ht_fnptr, fnptr, sizeof(fni->fnptr), &ttls.fn_infos[ttls.nr_fns]);
    ttls.nr_fns++;
    return 0;
}

static void tasvir_service_rpc_request(tasvir_msg_rpc *msg) {
    tasvir_fn_info *fni;
    HASH_FIND(h_fid, ttls.ht_fid, &msg->fid, sizeof(msg->fid), fni);
    assert(fni);
    fni->fnptr(msg->data, fni->arg_offsets);

    msg->h.dst_id = msg->h.src_id;
    msg->h.src_id = ttls.thread ? ttls.thread->id : ttls.any_src_id;
    msg->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
    // FIXME: time_us here means the update_ts of the area
    msg->h.time_us = ttls.local->time_us;
    tasvir_print_msg_rpc_info(msg, false);
    if (tasvir_route_msg((tasvir_msg *)msg, false) != 0) {
        TASVIR_LOG("FIXME: message not sent out!\n");
    }
}

static void tasvir_service_rpc_response(tasvir_msg_rpc *msg) {
    assert(msg->h.id < TASVIR_NR_RPC_MSG);
    tasvir_rpc_status *status = &ttls.status_l[msg->h.id];
    status->status = TASVIR_RPC_STATUS_DONE;
    status->response = msg;
}

static void tasvir_service_mem(tasvir_msg_mem *msg) {
    // TODO: log_write and sync
    /* static int i = 0;
    if (i++ % 100 == 0)
        TASVIR_LOG("%p %lu\n", msg->addr, msg->len); */
    tasvir_mov32blocks_stream(tasvir_data2shadow(msg->addr), msg->line, msg->len);
    tasvir_log_write(msg->addr, msg->len);
    if (!ttls.thread)
        tasvir_mov32blocks_stream(msg->addr, msg->line, msg->len);
}

static void tasvir_service_msg(tasvir_msg *msg) {
    if (tasvir_route_msg(msg, true) == 0) {
        return;
    }

    if (msg->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_print_msg_rpc_info((tasvir_msg_rpc *)msg, true);
        tasvir_service_rpc_request((tasvir_msg_rpc *)msg);
    } else if (msg->type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        tasvir_print_msg_rpc_info((tasvir_msg_rpc *)msg, true);
        tasvir_service_rpc_response((tasvir_msg_rpc *)msg);
    } else if (msg->type == TASVIR_MSG_TYPE_MEM) {
        tasvir_service_mem((tasvir_msg_mem *)msg);
    } else {
        TASVIR_LOG("received an unrecognized message type %d\n", msg->type);
    }
}

static void tasvir_service_port() {
    tasvir_msg *msg[TASVIR_RING_SIZE];
    unsigned int count, i, retval;

    count = rte_eth_rx_burst(ttls.local->dstate.port_id, 0, (struct rte_mbuf **)msg, TASVIR_RING_SIZE);
    for (i = 0; i < count; i++) {
        tasvir_service_msg(msg[i]);
    }

    while ((count = rte_ring_sc_dequeue_burst(ttls.local->ring_ext_tx, (void **)msg, TASVIR_RING_SIZE, NULL)) > 0) {
        for (i = 0; i < count; i++) {
            struct ether_hdr *eh = &msg[i]->eh;
            ether_addr_copy(&msg[i]->dst_id.nid.mac_addr, &eh->d_addr);
            ether_addr_copy(&ttls.local->dstate.mac_addr, &eh->s_addr);
            eh->ether_type = rte_cpu_to_be_16(TASVIR_ETH_PROTO);
        }

        i = 0;
        do {
            retval = rte_eth_tx_burst(ttls.local->dstate.port_id, 0, (struct rte_mbuf **)&msg[i], count - i);
            i += retval;
        } while (i < count);
    }
}

static void tasvir_service_ring(struct rte_ring *ring) {
    tasvir_msg *msg[TASVIR_RING_SIZE];
    unsigned int count, i;

    if (rte_ring_empty(ring))
        return;

    count = rte_ring_sc_dequeue_burst(ring, (void **)msg, TASVIR_RING_SIZE, NULL);
    for (i = 0; i < count; i++) {
        tasvir_service_msg(msg[i]);
    }
}

/* sync */
static inline void tasvir_schedule_sync(tasvir_area_desc *d) {
    if (!d->owner)
        return;

    tasvir_local_dstate *dstate = &ttls.local->dstate;
    size_t len, len_this, offset = 0;
    tasvir_sync_job *j;

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container *c = (tasvir_area_container *)d->h->data;
        len = sizeof(tasvir_area_header) + c->len;
    } else {
        len = d->len;
    }

    while (len > 0) {
        if (dstate->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
            TASVIR_LOG("more jobs than free slots\n");
            abort();
        }
        len_this = 1 + (len - 1) % TASVIR_SYNC_JOB_BYTES;
        j = &dstate->jobs[dstate->nr_jobs];
        j->old_version = d->h->version;
        j->d = d;
        j->offset = offset;
        j->len = len_this;
        j->bytes_changed = 0;

        dstate->nr_jobs++;
        offset += len_this;
        len -= len_this;
    }
}

static inline size_t tasvir_walk_areas(tasvir_area_desc *d, tasvir_area_desc_cb_fnptr fnptr) {
    size_t bytes = 0;
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container *c = (tasvir_area_container *)d->h->data;
        for (size_t i = 0; i < c->nr_areas; i++)
            bytes += tasvir_walk_areas(&c->descs[i], fnptr);
    }
    fnptr(d);
    return bytes;
}

static inline size_t tasvir_sync_job_helper_copy(uint8_t *src, tasvir_log_t *log_internal, size_t len, bool is_owner) {
    // FIXME: expects len to be aligned
    size_t nbits0 = 0;
    size_t nbits1 = 0;
    size_t nbits1_seen = 0;
    size_t nbits_seen = 0;
    size_t nbits_total = len >> TASVIR_SHIFT_BIT;
    uint8_t nbits_same;
    uint8_t nbits_unit_left = TASVIR_MIN(TASVIR_LOG_UNIT_BITS, nbits_total);

    tasvir_log_t *log = tasvir_data2log(src);
    tasvir_log_t log_val = *log;

    uint8_t *dst = is_owner ? tasvir_data2shadow(src) : src;
    src = is_owner ? src : tasvir_data2shadow(src);

    while (nbits_total > nbits_seen) {
        nbits_same = _lzcnt_u64(log_val);
        if (nbits_same > 0) {
            nbits_same = TASVIR_MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits0 += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val <<= nbits_same;
        }

        if (nbits_unit_left > 0) {
            if (nbits0 > 0) {
                size_t tmp = (nbits0 + nbits1) << TASVIR_SHIFT_BIT;
                /* copy over for a previous batch of 1s */
                tasvir_mov32blocks_stream(dst, src, nbits1 << TASVIR_SHIFT_BIT);
                src += tmp;
                dst += tmp;
                nbits0 = nbits1 = 0;
            }

            nbits_same = _lzcnt_u64(~log_val);
            nbits_same = TASVIR_MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits1 += nbits_same;
            nbits1_seen += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val = (log_val << (nbits_same - 1)) << 1;
        }

        if (nbits_unit_left == 0) {
            nbits_unit_left = TASVIR_MIN(TASVIR_LOG_UNIT_BITS, nbits_total - nbits_seen);
            *log_internal |= *log;
            log_internal++;
            *log = 0;
            log++;
            log_val = *log;
        }
    }
    if (nbits1 > 0) {
        tasvir_mov32blocks_stream(dst, src, nbits1 << TASVIR_SHIFT_BIT);
    }
    return nbits1_seen << TASVIR_SHIFT_BIT;
}

static inline void tasvir_sync_job_run(tasvir_sync_job *j) {
    size_t bytes = 0;

    /* FIXME: find the more recent desc */
    tasvir_area_desc *d = j->d->owner != NULL ? j->d : tasvir_data2shadow(j->d);
    uint16_t tid_owner = tasvir_is_thread_local(d->owner) ? d->owner->id.idx : 0;
    bool is_owner = tid_owner == ttls.thread->id.idx;
    tasvir_area_header *h = is_owner ? d->h : tasvir_data2shadow(d->h);

    if (h->d != j->d)
        return;

    /* special case for syncing root desc because it is an orphan */
    if (d == ttls.root_desc && j->offset == 0) {
        bytes = tasvir_sync_job_helper_copy((uint8_t *)j->d, h->diff_log[0].data,
                                            TASVIR_ALIGN(sizeof(tasvir_area_desc)), is_owner);
    }

    bytes += tasvir_sync_job_helper_copy((uint8_t *)d->h + j->offset,
                                         h->diff_log[0].data + (j->offset >> TASVIR_SHIFT_UNIT), j->len, is_owner);

    if (bytes > 0) {
        /* race doesn't matter because everyone is trying to update version to the same value */
        h = tasvir_data2shadow(d->h);
        d->h->version = h->version = d->h->diff_log[0].version_end = h->diff_log[0].version_end = j->old_version + 1;
        d->h->update_us = h->update_us = d->h->diff_log[0].ts_last_us = h->diff_log[0].ts_last_us = ttls.local->time_us;
        /* tasvir_memset_stream(tasvir_data2log((uint8_t *)d->h + j->offset), 0, j->len >> TASVIR_SHIFT_BYTE); */
    }

    j->bytes_changed = bytes;

    return;
}

static inline void tasvir_sync_prep() {
    tasvir_local_dstate *dstate = &ttls.local->dstate;
    if (ttls.local->time_us - dstate->last_sync_start < TASVIR_SYNC_INTERNAL_US) {
        return;
    }

    /* heartbeat: declare unresponsive threads dead */
    if (ttls.node) {
        for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
            if ((ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING) &&
                (ttls.local->time_us - ttls.local->tstate[i].update_us > ttls.node->heartbeat_us)) {
                tasvir_kill_thread(&ttls.node->threads[i]);
            }
        }
        ttls.local->barrier_entry = ttls.node->nr_threads;
        ttls.local->barrier_exit = ttls.node->nr_threads;
    } else {
        ttls.local->barrier_entry = 1;
        ttls.local->barrier_exit = 1;
    }

    dstate->nr_jobs = 0;
    atomic_store(&dstate->cur_job, 0);
    tasvir_walk_areas(ttls.root_desc, &tasvir_schedule_sync);

    if (ttls.node) {
        for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
            if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING) {
                ttls.local->tstate[i].sync = true;
            }
        }
    } else {
        ttls.local->tstate[0].sync = true;
    }
}

static inline void tasvir_sync_rotate_logs(tasvir_area_desc *d) {
    int i;
    uint64_t delta_us[3] = {500 * 1000, 15 * 1000 * 1000, 30 * 1000 * 1000};
    for (i = TASVIR_NR_AREA_LOGS - 2; i >= 0; i--) {
        tasvir_area_log *log = &d->h->diff_log[i];
        tasvir_area_log *log_next = &d->h->diff_log[i + 1];

        if (log->ts_last_us - log->ts_first_us > delta_us[i]) {
            tasvir_log_t *ptr = log->data;
            tasvir_log_t *ptr_next = log_next->data;
            tasvir_log_t *ptr_last = log_next->data;
            for (; ptr < ptr_last; ptr++, ptr_next++) {
                *ptr_next |= *ptr;
                *ptr = 0;
            }
            log->version_start = log_next->version_end = log->version_end;
            log->ts_first_us = log_next->ts_last_us = log->ts_last_us;
        }
    }
}

static inline void tasvir_msg_mem_generate(void *addr, size_t len, bool is_owner) {
    const int batch_size = 16;
    tasvir_msg_mem *msg[batch_size];
    tasvir_msg_mem *m;
    size_t i = 0;

    if (rte_mempool_get_bulk(ttls.local->mp, (void **)msg, batch_size)) {
        TASVIR_LOG("rte_mempool_get_bulk failed\n");
        // TODO: flush egress and retry
        abort();
    }

    while (len > 0) {
        m = msg[i];
        m->h.src_id = ttls.thread->id;
        m->h.dst_id = ttls.update_dst_id;
        m->h.id = ttls.nr_msgs++;
        m->h.type = TASVIR_MSG_TYPE_MEM;
        m->h.time_us = ttls.local->time_us;
        m->addr = addr;
        m->len = TASVIR_MIN(TASVIR_CACHELINE_BYTES * TASVIR_NR_CACHELINES_PER_MSG, len);
        m->h.mbuf.pkt_len = m->h.mbuf.data_len = m->len + offsetof(tasvir_msg_mem, line) - offsetof(tasvir_msg, eh);
        tasvir_mov32blocks_stream(m->line, is_owner ? tasvir_data2shadow(addr) : addr, m->len);

        addr = (uint8_t *)addr + m->len;
        len -= m->len;

        if (++i >= batch_size) {
            i = 0;
            if (rte_ring_sp_enqueue_bulk(ttls.local->ring_ext_tx, (void **)msg, batch_size, NULL) != batch_size) {
                TASVIR_LOG("rte_ring_sp_enqueue_bulk failed\n");
                // TODO: flush egress and retry
                abort();
            }
            tasvir_service_port();
            if (rte_mempool_get_bulk(ttls.local->mp, (void **)msg, batch_size)) {
                TASVIR_LOG("rte_mempool_get_bulk failed\n");
                // TODO: flush egress and retry
                abort();
            }
        }
    }

    size_t count = 0;
    if (i > 0) {
        count = rte_ring_sp_enqueue_bulk(ttls.local->ring_ext_tx, (void **)msg, i, NULL);
        if (count != i) {
            TASVIR_LOG("rte_ring_sp_enqueue_bulk failed\n");
            // TODO: flush egress and retry
            abort();
        }
        tasvir_service_port();
        rte_mempool_put_bulk(ttls.local->mp, (void **)&msg[i], batch_size - i);
    }
}

static inline void tasvir_sync_area_external(tasvir_area_desc *d, bool boot) {
    if (!d || !d->owner || !tasvir_is_thread_local(d->owner) || d->h->diff_log[0].version_end == 0)
        return;

    int i;
    size_t len;
    bool is_owner = tasvir_is_owner(d);

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container *c = (tasvir_area_container *)d->h->data;
        len = sizeof(tasvir_area_header) + c->len;
    } else {
        len = d->len;
    }

    if (!d->pd && ttls.is_root) {
        tasvir_msg_mem_generate(d, TASVIR_ALIGNX(sizeof(tasvir_area_desc), TASVIR_CACHELINE_BYTES), true);
    }

    size_t nbits0 = 0;
    size_t nbits1 = 0;
    size_t nbits1_seen = 0;
    size_t nbits_seen = 0;
    size_t nbits_total = len >> TASVIR_SHIFT_BIT;
    uint8_t nbits_same;
    uint8_t nbits_unit_left = TASVIR_MIN(TASVIR_LOG_UNIT_BITS, nbits_total);

    uint8_t *src = (uint8_t *)d->h;
    int pivot = 0;
    tasvir_log_t *log[4];
    for (i = 0; i < 4; i++) {
        log[i] = is_owner ? d->h->diff_log[i].data : tasvir_data2shadow(d->h->diff_log[i].data);
        if (!boot && d->h->diff_log[i].ts_last_us - ttls.local->time_us > TASVIR_SYNC_EXTERNAL_US) {
            break;
        }
        pivot++;
    }
    tasvir_log_t log_val = 0;
    for (i = 0; i < pivot; i++)
        log_val |= *log[i];

    while (nbits_total > nbits_seen) {
        nbits_same = _lzcnt_u64(log_val);
        if (nbits_same > 0) {
            nbits_same = TASVIR_MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits0 += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val <<= nbits_same;
        }

        if (nbits_unit_left > 0) {
            if (nbits0 > 0) {
                size_t tmp = (nbits0 + nbits1) << TASVIR_SHIFT_BIT;
                /* copy over for a previous batch of 1s */
                tasvir_msg_mem_generate(src, nbits1 << TASVIR_SHIFT_BIT, is_owner);
                src += tmp;
                nbits0 = nbits1 = 0;
            }

            nbits_same = _lzcnt_u64(~log_val);
            nbits_same = TASVIR_MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits1 += nbits_same;
            nbits1_seen += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val = (log_val << (nbits_same - 1)) << 1;
        }

        if (nbits_unit_left == 0) {
            nbits_unit_left = TASVIR_MIN(TASVIR_LOG_UNIT_BITS, nbits_total - nbits_seen);
            log_val = 0;
            for (i = 0; i < pivot; i++) {
                log[i]++;
                log_val |= *log[i];
            }
        }
    }
    if (nbits1 > 0) {
        tasvir_msg_mem_generate(src, nbits1 << TASVIR_SHIFT_BIT, is_owner);
    }
}

static inline void tasvir_sync_external() {
    tasvir_local_dstate *dstate = &ttls.local->dstate;
    if (ttls.local->time_us - dstate->last_sync_ext_start < TASVIR_SYNC_EXTERNAL_US)
        return;

    dstate->last_sync_ext_start = ttls.local->time_us;

    tasvir_walk_areas(ttls.root_desc, &tasvir_sync_area_external);

    ttls.local->time_us = tasvir_gettime_us();
    dstate->last_sync_ext_end = ttls.local->time_us;
}

static inline size_t tasvir_sync() {
    if (!ttls.thread)
        return 0;

    tasvir_local_tstate *tstate = &ttls.local->tstate[ttls.thread->id.idx];
    if (!tstate->sync)
        return 0;
    tasvir_local_dstate *dstate = &ttls.local->dstate;
    if (ttls.is_daemon)
        dstate->last_sync_start = tstate->update_us;

    size_t cur_job;
    uint64_t time_us = ttls.local->time_us;
    size_t total_bytes = 0;
    tstate->sync = false;

    if (tasvir_barrier_wait(&ttls.local->barrier_entry, TASVIR_BARRIER_ENTER_US) != 0) {
        TASVIR_LOG("tasvir_barrier_wait entry failed\n");
        return 0;
    }

    while ((cur_job = atomic_fetch_add(&dstate->cur_job, 1)) < dstate->nr_jobs) {
        tasvir_sync_job_run(&dstate->jobs[cur_job]);
        total_bytes += dstate->jobs[cur_job].bytes_changed;
    }
    _mm_sfence();

    if (tasvir_barrier_wait(&ttls.local->barrier_exit, TASVIR_BARRIER_EXIT_US) != 0) {
        TASVIR_LOG("tasvir_barrier_wait exit failed\n");
        return total_bytes;
    }

    tstate->update_us = tasvir_gettime_us();
    time_us = tstate->update_us - time_us;

    if (ttls.is_daemon) {
        for (cur_job = 0; cur_job < dstate->nr_jobs; cur_job++) {
            dstate->sync_stats_cur.cumbytes += dstate->jobs[cur_job].bytes_changed;
        }
        ttls.local->time_us = tstate->update_us;
        dstate->last_sync_end = tstate->update_us;
        dstate->sync_stats_cur.count++;
        dstate->sync_stats_cur.cumtime_us += time_us;

        tasvir_walk_areas(ttls.root_desc, &tasvir_sync_rotate_logs);
    }
    return total_bytes;
}

tasvir_sync_stats tasvir_sync_stats_get() { return ttls.local->dstate.sync_stats; }

void tasvir_sync_stats_reset() {
    memset(&ttls.local->dstate.sync_stats, 0, sizeof(tasvir_sync_stats));
    memset(&ttls.local->dstate.sync_stats_cur, 0, sizeof(tasvir_sync_stats));
}

static inline void tasvir_update_stats() {
    if (ttls.local->time_us - ttls.local->dstate.last_stat < TASVIR_STAT_US)
        return;

    ttls.local->dstate.last_stat = ttls.local->time_us;
    if (ttls.local->dstate.sync_stats_cur.count == 0)
        return;

    TASVIR_LOG("sync count %lu time %luus copied %lukB time/sync %luus copied/sync %lukB\n",
               ttls.local->dstate.sync_stats_cur.count, ttls.local->dstate.sync_stats_cur.cumtime_us,
               ttls.local->dstate.sync_stats_cur.cumbytes / 1000,
               ttls.local->dstate.sync_stats_cur.cumtime_us / ttls.local->dstate.sync_stats_cur.count,
               ttls.local->dstate.sync_stats_cur.cumbytes / (1000 * ttls.local->dstate.sync_stats_cur.count));

    ttls.local->dstate.sync_stats.count += ttls.local->dstate.sync_stats_cur.count;
    ttls.local->dstate.sync_stats.cumtime_us += ttls.local->dstate.sync_stats_cur.cumtime_us;
    ttls.local->dstate.sync_stats.cumbytes += ttls.local->dstate.sync_stats_cur.cumbytes;

    ttls.local->dstate.sync_stats_cur.count = 0;
    ttls.local->dstate.sync_stats_cur.cumtime_us = 0;
    ttls.local->dstate.sync_stats_cur.cumbytes = 0;
}

static inline void tasvir_service_daemon() {
    /* update time */
    ttls.local->time_us = tasvir_gettime_us();
    ttls.local->tstate[TASVIR_THREAD_DAEMON_IDX].update_us = ttls.local->time_us;
    /* service rings */
    if (ttls.node) {
        for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
            if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING ||
                ttls.node->threads[i].status == TASVIR_THREAD_STATUS_BOOTING) {
                tasvir_service_ring(ttls.local->tstate[i].ring_tx);
            }
        }
    }
    if (ttls.thread && ttls.thread->status == TASVIR_THREAD_STATUS_RUNNING)
        tasvir_sync_external();
    tasvir_service_port();
    if (ttls.thread && ttls.thread->status == TASVIR_THREAD_STATUS_RUNNING) {
        tasvir_update_stats();
        tasvir_sync_prep();
    }
}

static inline void tasvir_service_client() {
    /* service rings */
    if (likely(ttls.thread != NULL))
        ttls.local->tstate[ttls.thread->id.idx].update_us = ttls.local->time_us;
    uint16_t tid = ttls.thread ? ttls.thread->id.idx : TASVIR_THREAD_DAEMON_IDX;
    tasvir_service_ring(ttls.local->tstate[tid].ring_rx);
}

void tasvir_service() {
    if (ttls.is_daemon) {
        tasvir_service_daemon();
    } else {
        tasvir_service_client();
    }
    tasvir_sync();
}
