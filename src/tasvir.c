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
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#include "tasvir.h"

typedef void (*tasvir_area_desc_cb_fnptr)(tasvir_area_desc *);

typedef struct tasvir_local_tstate tasvir_local_tstate;
typedef struct tasvir_local_nstate tasvir_local_nstate;
typedef struct tasvir_tls_state tasvir_tls_state;

struct tasvir_local_tstate { /* thread state */
    uint64_t update_us;
    uint64_t timer_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    bool sync;
} __attribute__((aligned(8)));

struct tasvir_local_nstate { /* node state */
    uint64_t time_us;
    uint64_t tsc_hz;
    struct rte_mempool *mp;
    atomic_int barrier_entry;
    atomic_int barrier_exit;
    pthread_mutex_t mutex_boot;
    struct rte_ring *ring_ext_tx;

    /* daemon state */
    struct ether_addr mac_addr;
    uint8_t port_id;

    tasvir_tid update_tid;
    tasvir_tid broadcast_tid;
    tasvir_tid nodecast_tid;

    /* sync stats */
    uint64_t last_stat;
    uint64_t last_sync_start;
    uint64_t last_sync_end;
    uint64_t last_sync_ext_start;
    uint64_t last_sync_ext_end;
    tasvir_sync_stats sync_stats_cur;
    tasvir_sync_stats sync_stats;

    atomic_size_t cur_job;
    size_t nr_jobs;
    tasvir_sync_job jobs[TASVIR_NR_SYNC_JOBS];

    bool sync_req;

    /* thread state */
    tasvir_local_tstate tstate[TASVIR_NR_THREADS_LOCAL];
} __attribute__((aligned(8)));

struct tasvir_tls_state { /* thread-internal state */
    tasvir_area_desc *node_desc;
    tasvir_area_desc *root_desc;

    tasvir_local_nstate *nstate;
    tasvir_node *node;
    tasvir_thread *thread;

    bool is_root;
    bool is_daemon;
    uint16_t nr_msgs;
    int fd;
    int fd_huge;
    int nr_fns;
    tasvir_fn_info fn_infos[TASVIR_NR_FN];
    tasvir_fn_info *ht_fid;
    tasvir_fn_info *ht_fnptr;
    tasvir_rpc_status status_l[TASVIR_NR_RPC_MSG];
};

static tasvir_tls_state ttls;

_Static_assert(sizeof(tasvir_local_nstate) <= TASVIR_SIZE_LOCAL,
               "TASVIR_SIZE_LOCAL smaller than sizeof(tasvir_local_nstate)");

#define TASVIR_LOG(...)                                                                       \
    {                                                                                         \
        fprintf(stderr, "%14lu %-22.22s ", ttls.nstate ? ttls.nstate->time_us : 0, __func__); \
        fprintf(stderr, __VA_ARGS__);                                                         \
    }

#define TASVIR_MIN(x, y) (x < y ? x : y)

#define TASVIR_ALIGN_ARG(x) (size_t) TASVIR_ALIGNX(x, sizeof(tasvir_arg_promo_t))

/* function prototypes */

static inline int tasvir_attach_helper(tasvir_area_desc *, tasvir_node *);
static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type);
static inline void tasvir_init_finish(tasvir_thread *);
static inline size_t tasvir_sync_area_external_boot(tasvir_area_desc *d, bool boot);

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

static void rpc_tasvir_new(void *v, ptrdiff_t *o) { *(tasvir_area_desc **)R = tasvir_new(*(tasvir_area_desc *)X(0)); }

static void rpc_tasvir_set_owner(void *v, ptrdiff_t *o) {
    tasvir_set_owner(*(tasvir_area_desc **)X(0), *(tasvir_thread **)X(1));
}
#undef R
#undef X

/* utils */

static inline uint64_t tasvir_gettime_us() { return 1E6 * rte_rdtsc() / ttls.nstate->tsc_hz; }

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

static void tasvir_timer_init() { ttls.nstate->tstate[ttls.thread->tid.idx].timer_us = tasvir_gettime_us(); }

static bool tasvir_timer_expired(uint64_t timeout_us) {
    return tasvir_gettime_us() - ttls.nstate->tstate[ttls.thread->tid.idx].timer_us > timeout_us;
}

static inline int tasvir_barrier_wait(atomic_int *count, int64_t timeout_us) {
    uint64_t end_time_us = tasvir_gettime_us() + timeout_us;
    int val = atomic_fetch_sub(count, 1) - 1;
    while (val > 0) {
        if (tasvir_gettime_us() > end_time_us && atomic_compare_exchange_weak(count, &val, -1))
            break;
        rte_delay_us_block(1);
        val = atomic_load(count);
    }
    // invariant: *count is non-positive at the end
    return val != 0;
}

static inline bool tasvir_is_attached(tasvir_area_desc *d, tasvir_node *node) {
    if (d->h && d->h->active)
        for (size_t i = 0; i < d->h->nr_users; i++)
            if (d->h->users[i].node == node)
                return true;
    return false;
}

static inline bool tasvir_is_owner(const tasvir_area_desc *d) {
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

static inline size_t tasvir_size_loggable(const tasvir_area_desc *d) {
    return (size_t)TASVIR_ALIGN((d->type == TASVIR_AREA_TYPE_CONTAINER
                                     ? (sizeof(tasvir_area_header) + d->nr_areas_max + sizeof(tasvir_area_desc))
                                     : d->len));
}

static inline bool tasvir_tid_match(const tasvir_tid *id, const tasvir_tid_type t) {
    switch (t) {
    case TASVIR_TID_BROADCAST:
        return memcmp(id, &ttls.nstate->broadcast_tid, sizeof(tasvir_tid)) == 0;
    case TASVIR_TID_UPDATE:
        return memcmp(id, &ttls.nstate->update_tid, sizeof(tasvir_tid)) == 0;
    case TASVIR_TID_LOCAL:
        return memcmp(&id->nid, ttls.node ? &ttls.node->nid : &ttls.nstate->nodecast_tid.nid, sizeof(tasvir_nid)) == 0;
    case TASVIR_TID_DEFAULT:
        return true;
    default:
        return false;
    }
}

static inline bool tasvir_is_thread_local(tasvir_thread *t) { return tasvir_tid_match(&t->tid, TASVIR_TID_LOCAL); }

static inline void tasvir_tid2str(tasvir_tid *tid, size_t buf_size, char *buf) {
    ether_format_addr(buf, buf_size, &tid->nid.mac_addr);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), ":%d", tid->idx);
}

static inline void tasvir_print_msg_rpc_info(tasvir_msg_rpc *msg, bool inbound) {
    tasvir_str src_str, dst_str;
    tasvir_tid2str(&msg->h.src_tid, sizeof(src_str), src_str);
    tasvir_tid2str(&msg->h.dst_tid, sizeof(dst_str), dst_str);
    TASVIR_LOG("%s %s->%s id=%d type=%s desc=%s fid=%d\n", inbound ? "incoming" : "outgoing", src_str, dst_str,
               msg->h.id, msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST ? "request" : "response",
               msg->d ? msg->d->name : "ROOT", msg->fid);
    // tasvir_hexdump(&msg->h.eh, msg->h.mbuf.data_len);
}

static inline void tasvir_change_vaddr(void *base1, void *base2, size_t len, bool swap) {
    void *ret;
    ptrdiff_t base1_rel = (uint8_t *)(swap ? base2 : base1) - (uint8_t *)TASVIR_ADDR_BASE;
    ptrdiff_t base2_rel = (uint8_t *)(swap ? base1 : base2) - (uint8_t *)TASVIR_ADDR_BASE;
    TASVIR_LOG("%s %p<->%p %lu\n", swap ? "swap" : "revert", base1, base2, len);
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
    /*
    bool test = false;
    if (src == 0x100000001000 || dst == 0x100000001000) {
        test = true;
        tasvir_area_desc *d1 = 0x100000001010;
        tasvir_area_desc *d2 = 0x140000001010;
        printf("TEST BEFORE h=%p h=%p\n", d1->h, d2->h);
    }
    TASVIR_LOG("%p->%p %lu\n", src, dst, len);
    */
    while (len > 0) {
        tasvir_mov32_stream(dst, src);
        /* rte_mov32(dst, src); */
        len -= 32;
        dst = (uint8_t *)dst + 32;
        src = (uint8_t *)src + 32;
    }
    /*
    if (test) {
        tasvir_area_desc *d1 = 0x100000001010;
        tasvir_area_desc *d2 = 0x140000001010;
        printf("TEST AFTER h=%p h=%p\n", d1->h, d2->h);
    }
    */
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
                                          .argc = 1,
                                          .ret_len = sizeof(tasvir_area_desc *),
                                          .arg_lens = {sizeof(tasvir_area_desc)}});
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
    snprintf(base_virtaddr, sizeof(base_virtaddr), "%lx", TASVIR_ADDR_DPDK_BASE);
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
    ttls.nstate->port_id = 0;
    rte_eth_macaddr_get(ttls.nstate->port_id, &ttls.nstate->mac_addr);
    ether_addr_copy(&ttls.nstate->mac_addr, &ttls.nstate->nodecast_tid.nid.mac_addr);

    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf *rx_conf;
    struct rte_eth_txconf *tx_conf;
    struct rte_eth_link link;
    uint64_t end_time_us;
    int retval;

    /* prepare configs */
    memset(&port_conf, 0, sizeof(port_conf));
    rte_eth_dev_info_get(ttls.nstate->port_id, &dev_info);
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

    retval = rte_eth_dev_configure(ttls.nstate->port_id, 1, 1, &port_conf);
    if (retval < 0) {
        TASVIR_LOG("Cannot configure device: err=%d, port=%d\n", retval, ttls.nstate->port_id);
        return -1;
    }

    retval = rte_eth_rx_queue_setup(ttls.nstate->port_id, 0, 4096, rte_eth_dev_socket_id(ttls.nstate->port_id), rx_conf,
                                    ttls.nstate->mp);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_rx_queue_setup:err=%d, port=%u\n", retval, (unsigned)ttls.nstate->port_id);
        return -1;
    }

    retval =
        rte_eth_tx_queue_setup(ttls.nstate->port_id, 0, 4096, rte_eth_dev_socket_id(ttls.nstate->port_id), tx_conf);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_tx_queue_setup:err=%d, port=%u\n", retval, (unsigned)ttls.nstate->port_id);
        return -1;
    }

    retval = rte_eth_dev_start(ttls.nstate->port_id);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_dev_start: err=%d, port=%u\n", retval, ttls.nstate->port_id);
        return -1;
    }

    retval = rte_eth_dev_set_link_up(ttls.nstate->port_id);
    if (retval < 0) {
        TASVIR_LOG("rte_eth_dev_set_link_up: err=%d, port=%u\n", retval, ttls.nstate->port_id);
        return -1;
    }

    end_time_us = tasvir_gettime_us() + 5 * 1000 * 1000;
    do {
        rte_eth_link_get(ttls.nstate->port_id, &link);
    } while (tasvir_gettime_us() < end_time_us && link.link_status != ETH_LINK_UP);

    if (link.link_status != ETH_LINK_UP) {
        TASVIR_LOG("rte_eth_link_get_nowait: link is down port=%u\n", ttls.nstate->port_id);
        return -1;
    }

    rte_eth_promiscuous_enable(ttls.nstate->port_id);
    rte_eth_stats_reset(ttls.nstate->port_id);
    rte_eth_xstats_reset(ttls.nstate->port_id);

    tasvir_str buf;
    ether_format_addr(buf, sizeof(buf), &ttls.nstate->mac_addr);
    TASVIR_LOG("port=%d mac=%s\n", ttls.nstate->port_id, buf);

    return 0;
}

static int tasvir_init_local() {
    void *base;
    int shm_oflag = ttls.is_daemon ? O_CREAT | O_EXCL | O_RDWR : O_RDWR;
    mode_t shm_mode = ttls.is_daemon ? S_IRUSR | S_IWUSR : 0;
    ptrdiff_t size_whole = TASVIR_ADDR_END - TASVIR_ADDR_BASE;

    ttls.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttls.fd == -1)
        return -1;
    if (ftruncate(ttls.fd, size_whole)) {
        TASVIR_LOG("ftruncate failed (%s)\n", strerror(errno));
        return -1;
    }
    base = mmap((void *)TASVIR_ADDR_BASE, size_whole, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttls.fd, 0);
    if (base != (void *)TASVIR_ADDR_BASE) {
        TASVIR_LOG("mmap failed\n");
        return -1;
    }

    ttls.nstate = (void *)TASVIR_ADDR_LOCAL;

    if (ttls.is_daemon) {
        memset(ttls.nstate, 0, sizeof(tasvir_local_nstate));
        /* boot mutex */
        pthread_mutexattr_t mutex_attr;
        pthread_mutexattr_init(&mutex_attr);
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ttls.nstate->mutex_boot, &mutex_attr);
        pthread_mutexattr_destroy(&mutex_attr);

        /* mempool */
        ttls.nstate->mp =
            rte_pktmbuf_pool_create("mempool", 200 * 1024, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!ttls.nstate->mp) {
            TASVIR_LOG("failed to create pkt mempool\n");
            return -1;
        }

        /* tx ring */
        ttls.nstate->ring_ext_tx =
            rte_ring_create("tasvir_ext_tx", TASVIR_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (ttls.nstate->ring_ext_tx == NULL) {
            TASVIR_LOG("failed to create external rings");
            return -1;
        }

        /* timing */
        ttls.nstate->tsc_hz = rte_get_tsc_hz();

        /* ids */
        ttls.nstate->update_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x00}}};
        ttls.nstate->update_tid.idx = -1;
        ttls.nstate->update_tid.pid = -1;
        ttls.nstate->broadcast_tid.nid = (tasvir_nid){.mac_addr = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}};
        ttls.nstate->broadcast_tid.idx = -1;
        ttls.nstate->broadcast_tid.pid = -1;
        ttls.nstate->nodecast_tid = ttls.nstate->broadcast_tid;
    } else {
        uint64_t end_time_us = tasvir_gettime_us() + 1 * 1000 * 1000;
        while (tasvir_gettime_us() < end_time_us && !ttls.nstate->tstate[TASVIR_THREAD_DAEMON_IDX].ring_tx) {
            rte_delay_ms(1);
        }
        if (!ttls.nstate->tstate[TASVIR_THREAD_DAEMON_IDX].ring_tx) {
            TASVIR_LOG("daemon has not yet initialized the bootstrap ring\n");
            return -1;
        }
    }

    return 0;
}

static int tasvir_init_root() {
    ttls.root_desc = (tasvir_area_desc *)TASVIR_ADDR_ROOT_DESC;
    tasvir_area_desc *d_ret;

    if (ttls.is_root) {
        d_ret = tasvir_new((tasvir_area_desc){.pd = NULL,
                                              .owner = NULL,
                                              .type = TASVIR_AREA_TYPE_CONTAINER,
                                              .name = "root",
                                              .len = TASVIR_SIZE_DATA - 2 * TASVIR_HUGEPAGE_SIZE,
                                              .nr_areas_max = TASVIR_NR_AREAS_MAX,
                                              .stale_us = 50000});
    } else {
        uint64_t end_time_us = tasvir_gettime_us() + 500 * 1000;
        while (tasvir_gettime_us() < end_time_us && !(d_ret = tasvir_attach(NULL, "root", NULL))) {
            rte_delay_ms(1);
        }
    }

    if (!d_ret || !d_ret->active) {
        TASVIR_LOG("root not initialized\n")
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
    ether_format_addr(&name[strlen(name)], sizeof(name) - strlen(name), &ttls.nstate->mac_addr);

    if (ttls.is_daemon) {
        /* id and address */
        /* initializing boot_us so that could be later use this node's clock rather than root's */
        ttls.node_desc = tasvir_new((tasvir_area_desc){.pd = ttls.root_desc,
                                                       .owner = NULL,
                                                       .type = TASVIR_AREA_TYPE_NODE,
                                                       .name_static = *(tasvir_str_static *)name,
                                                       .len = sizeof(tasvir_node),
                                                       .nr_areas_max = 0,
                                                       .boot_us = tasvir_gettime_us(),
                                                       .stale_us = 50000});
        if (!ttls.node_desc) {
            TASVIR_LOG("failed to allocate node\n");
            return -1;
        }
        ttls.node = tasvir_data(ttls.node_desc);
        memset(ttls.node, 0, sizeof(tasvir_node));
        ether_addr_copy(&ttls.nstate->mac_addr, &ttls.node->nid.mac_addr);
        ttls.node->heartbeat_us = TASVIR_HEARTBEAT_US;

        /* time */
        tasvir_log_write(ttls.node, sizeof(tasvir_node));
    } else {
        uint64_t end_time_us = tasvir_gettime_us() + 500 * 1000;
        while (tasvir_gettime_us() < end_time_us && !(ttls.node_desc = tasvir_attach(ttls.root_desc, name, NULL)))
            rte_delay_ms(1);
        if (!ttls.node_desc->h->active) {
            TASVIR_LOG("node not initiliazed yet\n");
            return -1;
        }
        ttls.node = tasvir_data(ttls.node_desc);

        tasvir_local_tstate *daemon_tstate = &ttls.nstate->tstate[TASVIR_THREAD_DAEMON_IDX];

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
        t->tid.nid = ttls.node->nid;
        t->tid.idx = tid;
        t->tid.pid = pid;
        t->status = TASVIR_THREAD_STATUS_BOOTING;

        tasvir_local_tstate *tstate = &ttls.nstate->tstate[tid];
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
        pthread_mutex_lock(&ttls.nstate->mutex_boot);
        t = tasvir_rpc_sync(ttls.node_desc, 1 * 1000 * 1000, &rpc_tasvir_init_thread, pid, core, type);
        pthread_mutex_unlock(&ttls.nstate->mutex_boot);
    }

    if (t)
        TASVIR_LOG("addr=%p tid=%d core=%d pid=%d status=%d\n", (void *)t, t->tid.idx, t->core, t->tid.pid, t->status);

    return t;
}

static inline void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c[i]);
    }
    if (d->owner == t)
        tasvir_set_owner(d, NULL);
}

static inline void tasvir_kill_thread(tasvir_thread *t) {
    assert(ttls.is_daemon && tasvir_is_thread_local(t));
    tasvir_local_tstate *tstate = &ttls.nstate->tstate[t->tid.idx];
    TASVIR_LOG("thread=%d idle_time=%zd remaining_threads=%lu\n", t->tid.idx, ttls.nstate->time_us - tstate->update_us,
               ttls.node->nr_threads - 1);
    tstate->sync = false;
    tstate->update_us = 0;

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttls.root_desc);

    /* kill by pid */
    /* kill(t->tid.pid, SIGKILL); */

    ttls.node->nr_threads--;
    tasvir_log_write(&ttls.node->nr_threads, sizeof(ttls.node->nr_threads));
    t->status = TASVIR_THREAD_STATUS_DEAD;
    tasvir_log_write(&t->status, sizeof(t->status));

    rte_ring_free(ttls.nstate->tstate[t->tid.idx].ring_rx);
    rte_ring_free(ttls.nstate->tstate[t->tid.idx].ring_tx);
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
            if (ttls.is_root) {
                ttls.node_desc->owner = ttls.thread;
                tasvir_log_write(&ttls.root_desc->owner, sizeof(tasvir_thread *));
                ttls.root_desc->owner = ttls.thread;
            } else {
                tasvir_set_owner(ttls.node_desc, ttls.thread);
            }
        }
    } else {
        tasvir_rpc_sync(ttls.node_desc, 1 * 1000 * 1000, &rpc_tasvir_init_finish, t);
    }

    TASVIR_LOG("tid=%d core=%d pid=%d\n", t->tid.idx, t->core, t->tid.pid);
}

tasvir_area_desc *tasvir_init(uint8_t type, uint16_t core, char *pciaddr) {
    assert(!ttls.node && !ttls.thread);

    memset(&ttls, 0, sizeof(tasvir_tls_state));
    ttls.is_daemon = type == TASVIR_THREAD_TYPE_DAEMON || type == TASVIR_THREAD_TYPE_ROOT;
    ttls.is_root = type == TASVIR_THREAD_TYPE_ROOT;

    tasvir_init_rpc();

    TASVIR_LOG("dpdk\n");
    if (tasvir_init_dpdk(core, pciaddr)) {
        TASVIR_LOG("tasvir_init_dpdk failed\n");
        return NULL;
    }

    TASVIR_LOG("local\n");
    if (tasvir_init_local()) {
        TASVIR_LOG("tasvir_init_local failed\n");
        return NULL;
    }

    TASVIR_LOG("port\n");
    if (tasvir_init_port(pciaddr)) {
        TASVIR_LOG("tasvir_init_port failed\n");
        return NULL;
    }

    TASVIR_LOG("root\n");
    if (tasvir_init_root()) {
        TASVIR_LOG("tasvir_init_root failed\n");
        return NULL;
    }

    TASVIR_LOG("node\n");
    if (tasvir_init_node()) {
        TASVIR_LOG("tasvir_init_node failed\n");
        return NULL;
    }

    TASVIR_LOG("thread\n");
    ttls.thread = tasvir_init_thread(getpid(), core, type);
    if (!ttls.thread) {
        TASVIR_LOG("tasvir_init_thread failed\n");
        return NULL;
    }

    TASVIR_LOG("finish\n");
    tasvir_init_finish(ttls.thread);

    return ttls.root_desc;
}

/* area management */

tasvir_area_desc *tasvir_new(tasvir_area_desc desc) {
    desc.active = false;
    tasvir_area_desc *d = NULL;
    tasvir_area_container c = NULL;
    uint64_t time_us = tasvir_gettime_us();
    bool is_root_area = !desc.pd;
    bool is_desc_owner = tasvir_is_owner(desc.pd);
    bool is_owner = desc.type == TASVIR_AREA_TYPE_NODE ? !ttls.node : tasvir_is_owner(&desc);
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;

    if ((is_container && desc.nr_areas_max == 0) || (!is_container && desc.nr_areas_max != 0)) {
        TASVIR_LOG("mismatch between type and number of subareas (type=%s,nr_areas_max=%lu)\n",
                   tasvir_area_type_str[desc.type], desc.nr_areas_max);
        return NULL;
    }
    if (!desc.owner && desc.type != TASVIR_AREA_TYPE_NODE)
        desc.owner = ttls.thread;
    if ((is_root_area && !is_container) || (!is_root_area && desc.pd->type != TASVIR_AREA_TYPE_CONTAINER)) {
        TASVIR_LOG("incorrect area type\n");
        return NULL;
    }

    size_t i;
    size_t size_metadata = sizeof(tasvir_area_header) + desc.nr_areas_max * sizeof(tasvir_area_desc);
    size_t size_data = desc.len;
    size_t size_loggable = tasvir_size_loggable(&desc);
    size_t size_log = TASVIR_ALIGNX((size_loggable >> TASVIR_SHIFT_BYTE), 8 * sizeof(tasvir_log_t));
    desc.len = TASVIR_ALIGN((size_metadata + size_data)) + TASVIR_NR_AREA_LOGS * size_log;

    assert(is_root_area || desc.pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(!is_root_area || is_container);

    /* initialize area descriptor */
    if (is_desc_owner) {
        void *h = NULL;
        if (is_root_area) {
            d = ttls.root_desc;
            h = (void *)TASVIR_ADDR_DATA;
        } else {
            c = tasvir_data(desc.pd);

            /* ensure enough descriptors */
            if (desc.pd->h->nr_areas >= desc.pd->nr_areas_max) {
                TASVIR_LOG("out of descriptors\n");
                return NULL;
            }

            /* ensure area does not exist */
            for (i = 0; i < desc.pd->h->nr_areas; i++) {
                if (strncmp(c[i].name, desc.name, sizeof(tasvir_str)) == 0) {
                    TASVIR_LOG("area exists\n");
                    return NULL;
                }
            }

            size_t *nr_areas = &desc.pd->h->nr_areas;
            d = &c[*nr_areas];
            h = (void *)TASVIR_ALIGN((*nr_areas > 0 ? (uint8_t *)c[*nr_areas - 1].h + c[*nr_areas - 1].len
                                                    : (uint8_t *)c + desc.pd->nr_areas_max * sizeof(tasvir_area_desc)));
            if ((uint8_t *)h + desc.len > (uint8_t *)desc.pd->h + desc.pd->len) {
                TASVIR_LOG("out of space\n");
                return NULL;
            }
            (*nr_areas)++;
            tasvir_log_write(nr_areas, sizeof(*nr_areas));
        }
        memcpy(d, &desc, sizeof(tasvir_area_desc));
        d->h = h;
        if (d->boot_us == 0)
            d->boot_us = time_us;
        d->active = true;
        tasvir_log_write(d, sizeof(tasvir_area_desc));
    } else {
        d = tasvir_rpc_sync(desc.pd, 1 * 1000 * 1000, &rpc_tasvir_new, desc);
    }

    if (!d || !d->active || !d->h) {
        TASVIR_LOG("invalid descriptor: d=%p, d->active=%d, d->h=%p\n", (void *)d, d ? d->active : false,
                   d ? (void *)d->h : NULL);
        return NULL;
    }

    if (is_owner) {
        tasvir_set_owner(d, ttls.thread);
        memset(d->h, 0, size_metadata);
        d->h->d = d;
        d->h->version = 0;
        d->h->update_us = time_us;
        d->h->nr_areas = 0;
        d->h->nr_users = 1;
        d->h->users[0].node = ttls.node;
        d->h->users[0].version = 0;
        for (i = 0; i < TASVIR_NR_AREA_LOGS; i++) {
            tasvir_area_log *log = &d->h->diff_log[i];
            log->version_start = 0;
            log->version_end = 0;
            log->ts_first_us = time_us;
            log->ts_last_us = 0;
            log->data = (tasvir_log_t *)((uint8_t *)d->h + d->len - (TASVIR_NR_AREA_LOGS - i) * size_log);
        }
        d->h->active = true;
        tasvir_log_write(d->h, sizeof(tasvir_area_header));
    }

    TASVIR_LOG(
        "name=%s type=%s len=%lx stale_us=%lu boot_us=%lu nr_areas_max=%lu immediate=%s active=%s "
        "d=%p pd=%p owner=%p h=%p is_desc_owner=%s is_owner=%s\n",
        d->name, tasvir_area_type_str[d->type], d->len, d->stale_us, d->boot_us, d->nr_areas_max,
        d->immediate ? "true" : "false", d->active ? "true" : "false", (void *)d, (void *)d->pd, (void *)d->owner,
        (void *)d->h, is_desc_owner ? "true" : "false", is_owner ? "true" : "false");

    return d;
}

int tasvir_delete(tasvir_area_desc *d) {
    /* TODO: sanity check (d, d->pd, etc) */

    /* TODO: remove from d->pd */
    if (tasvir_is_owner(d->pd)) {
        d->active = false;
    } else {
        return *(int *)tasvir_rpc_sync(d->pd, 1 * 1000 * 1000, &rpc_tasvir_delete, d);
    }
    return 0;
}

static inline int tasvir_attach_helper(tasvir_area_desc *d, tasvir_node *node) {
    if (tasvir_is_attached(d, node)) {
        return 0;
    }

    if (tasvir_is_owner(d)) {
        if (d->h->nr_users >= TASVIR_NR_NODES_AREA) {
            TASVIR_LOG("%s has reached max number of subscribers\n", d->name);
            return -1;
        }

        tasvir_log_write(&d->h->users[d->h->nr_users], sizeof(tasvir_area_user));
        if (node) {
            d->h->users[d->h->nr_users].node = node;
            d->h->users[d->h->nr_users].version = 0;
            d->h->nr_users++;
        }

        tasvir_sync_area_external_boot(d, true);
        /* FIXME: hack to receive thread id info */
        if (d == ttls.root_desc) {
            tasvir_area_container c = tasvir_data(d);
            for (size_t i = 0; i < d->h->nr_areas; i++)
                if (c[i].type == TASVIR_AREA_TYPE_NODE)
                    tasvir_sync_area_external_boot(&c[i], true);
        }
    } else if (ttls.thread) {
        tasvir_rpc_sync(d, 1 * 1000 * 1000, &rpc_tasvir_attach_helper, d, node);
    }

    return !tasvir_is_attached(d, node);
}

tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, const char *name, tasvir_node *node) {
    /* TODO: sanity checking? */
    tasvir_area_desc *d = NULL;

    if (!pd) /* root_area */
        d = ttls.root_desc;
    else if (pd->active && pd->type == TASVIR_AREA_TYPE_CONTAINER && pd->h && pd->h->active) {
        tasvir_area_container c = tasvir_data(pd);
        for (size_t i = 0; i < pd->h->nr_areas; i++) {
            if (strncmp(c[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &c[i];
                break;
            }
        }
    }

    /* FIXME: header check necessary? */
    if (!(d && d->active && d->h && d->owner))
        return NULL;

    if (!d->h->active)
        tasvir_attach_helper(d, node ? node : ttls.node);

    if (!d->h->active)
        return NULL;

    TASVIR_LOG("name=%s len=%lu h=%p\n", d->name, d->len, (void *)d->h);
    return d;
}

int tasvir_detach(tasvir_area_desc *d) {
    /* TODO: sanity check */
    /* TODO: update subscriber's list */

    return 0;
}

void tasvir_set_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    tasvir_thread *desc_owner = d->pd ? d->pd->owner : d->owner;
    bool is_new_owner = owner == ttls.thread;
    bool is_old_owner = d->owner == ttls.thread;
    bool is_desc_owner = desc_owner == ttls.thread;
    void *base = d->h;
    void *base_shadow = tasvir_data2shadow(base);

    if (is_desc_owner) {
        d->owner = owner;
        tasvir_log_write(&d->owner, sizeof(d->owner));
    }

    if (!d->immediate) {
        if (is_new_owner) {
            tasvir_change_vaddr(base, base_shadow, tasvir_size_loggable(d), true);

            /* FIXME: change to async and wait for change to propagate */
            if (d->owner && !is_old_owner) {
                /* rpc to previous owner */
                tasvir_rpc_sync(d, 1 * 1000 * 1000, &rpc_tasvir_set_owner, d, owner);
            }

            if (desc_owner && !is_desc_owner) {
                /* rpc to desc owner */
                tasvir_rpc_sync(d->pd, 1 * 1000 * 1000, &rpc_tasvir_set_owner, d, owner);
            }
        } else if (is_old_owner) {
            /* restore the mappings of the old owner */
            tasvir_change_vaddr(base, base_shadow, tasvir_size_loggable(d), false);
        }
    }
}

/* rpc */

/* return 0 if message sent out */
static int tasvir_route_msg(tasvir_msg *msg, bool inbound) {
    /* destination broadcast is only meant for the root daemon */
    bool is_dst_any = tasvir_tid_match(&msg->dst_tid, TASVIR_TID_BROADCAST);
    bool is_dst_update = tasvir_tid_match(&msg->dst_tid, TASVIR_TID_UPDATE);
    bool is_dst_local = is_dst_any ? ttls.is_root || msg->type == TASVIR_MSG_TYPE_MEM
                                   : is_dst_update || tasvir_tid_match(&msg->dst_tid, TASVIR_TID_LOCAL);
    bool is_dst_me = inbound && is_dst_local && ((is_dst_any && ttls.is_root) || (is_dst_update && ttls.is_daemon) ||
                                                 !ttls.thread || msg->dst_tid.idx == ttls.thread->tid.idx);
    struct rte_ring *r;

    if (is_dst_me || (inbound && !ttls.is_daemon)) {
        /* no-op when message is ours or reached here by error */
        return -1;
    } else if (ttls.is_daemon) {
        uint16_t tid = msg->dst_tid.idx == (uint16_t)(-1) ? TASVIR_THREAD_DAEMON_IDX : msg->dst_tid.idx;
        r = is_dst_local ? ttls.nstate->tstate[tid].ring_rx : ttls.nstate->ring_ext_tx;
    } else {
        uint16_t tid = ttls.thread ? ttls.thread->tid.idx : TASVIR_THREAD_DAEMON_IDX;
        r = ttls.nstate->tstate[tid].ring_tx;
    }

    if (rte_ring_sp_enqueue(r, msg) != 0) {
        TASVIR_LOG("rte_ring_sp_enqueue failed\n");
        rte_mempool_put(ttls.nstate->mp, (void *)msg);
        abort();
        return -1;
    }

    return 0;
}

static tasvir_rpc_status *tasvir_vrpc_async(tasvir_area_desc *d, tasvir_fnptr fnptr, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *msg;
    if (rte_mempool_get(ttls.nstate->mp, (void **)&msg)) {
        TASVIR_LOG("rte_mempool_get failed\n");
        return NULL;
    }

    tasvir_fn_info *fni;
    HASH_FIND(h_fnptr, ttls.ht_fnptr, &fnptr, sizeof(fnptr), fni);
    assert(fni);

    /* FIXME: using daemon id as src during boot to simplify impl */
    msg->h.src_tid = ttls.thread ? ttls.thread->tid : ttls.nstate->nodecast_tid;
    msg->h.dst_tid = d && d->owner ? d->owner->tid : ttls.nstate->broadcast_tid;
    msg->h.id = ttls.nr_msgs++;
    msg->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    msg->h.time_us = d && d->h ? d->h->update_us : ttls.nstate->time_us;
    msg->d = d;
    msg->fid = fni->fid;
    ptr = &msg->data[TASVIR_ALIGN_ARG(fni->ret_len)];

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
    msg->h.mbuf.pkt_len = msg->h.mbuf.data_len =
        TASVIR_ALIGN_ARG((fni->argc > 0 ? fni->arg_lens[i - 1] : 0) + ptr - (uint8_t *)&msg->h.eh);

    tasvir_print_msg_rpc_info((tasvir_msg_rpc *)msg, false);
    if (tasvir_route_msg((tasvir_msg *)msg, false) != 0) {
        return NULL;
    }

    tasvir_rpc_status *rs = &ttls.status_l[msg->h.id];
    /* garbage collect a previous status */
    if (rs->response)
        rte_mempool_put(ttls.nstate->mp, (void *)rs->response);
    rs->id = msg->h.id;
    rs->status = TASVIR_RPC_STATUS_PENDING;
    rs->response = NULL;
    rs->cb = NULL;
    return rs;
}

tasvir_rpc_status *tasvir_rpc_async(tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc_async(d, fnptr, argp);
    va_end(argp);
    return rs;
}

void *tasvir_rpc_sync(tasvir_area_desc *d, uint64_t timeout_us, tasvir_fnptr fnptr, ...) {
    bool done = false;
    uint64_t end_time_us = tasvir_gettime_us() + timeout_us;
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc_async(d, fnptr, argp);
    va_end(argp);

    /* FIXME: horrible error handling */
    while (!done && ttls.nstate->time_us < end_time_us) {
        switch (rs->status) {
        case TASVIR_RPC_STATUS_INVALID:
        case TASVIR_RPC_STATUS_FAILED:
            return NULL;
        case TASVIR_RPC_STATUS_PENDING:
            break;
        case TASVIR_RPC_STATUS_DONE:
            if (!(rs->response && rs->response->d && rs->response->d->h)) {
                TASVIR_LOG("bad response\n");
                return NULL;
            }
            /* FIXME: find a better way to ensure state is visible */
            done = (rs->response->d->h->update_us >= rs->response->h.time_us) ||
                   (rs->response->d->immediate && tasvir_is_thread_local(rs->response->d->owner));
            break;
        default:
            TASVIR_LOG("invalid rpc status %d\n", rs->status);
            return NULL;
        }
        tasvir_service();
    }

    if (!done) {
        TASVIR_LOG("failed (status=%d h=%p update_us=%lu expected_us=%lu)\n", rs->status,
                   rs->response ? (void *)rs->response->d->h : NULL, rs->response ? rs->response->d->h->update_us : 0,
                   rs->response ? rs->response->h.time_us : 0);
        return NULL;
    } else
        return *(void **)rs->response->data;
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

    /* convert the message into a response */
    msg->h.dst_tid = msg->h.src_tid;
    msg->h.src_tid = ttls.thread ? ttls.thread->tid : ttls.nstate->nodecast_tid;
    msg->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
    /* receiver compares time_us with update_us of the area to ensure it includes the updates due to this msg */
    msg->h.time_us = ttls.nstate->time_us;
    tasvir_print_msg_rpc_info(msg, false);

    /* execute the function */
    fni->fnptr(msg->data, fni->arg_offsets);

    if (tasvir_route_msg((tasvir_msg *)msg, false) != 0) {
        TASVIR_LOG("FIXME: message not sent out!\n");
    }
}

static void tasvir_service_rpc_response(tasvir_msg_rpc *msg) {
    assert(msg->h.id < TASVIR_NR_RPC_MSG);
    tasvir_rpc_status *rs = &ttls.status_l[msg->h.id];
    rs->status = TASVIR_RPC_STATUS_DONE;
    rs->response = msg;
}

static void tasvir_service_msg_mem(tasvir_msg_mem *msg) {
    /* TODO: log_write and sync */
    ttls.nstate->sync_stats_cur.cumbytes_rx += msg->len;
    ttls.nstate->sync_stats_cur.cumpkts_rx++;
    tasvir_mov32blocks_stream(tasvir_data2shadow(msg->addr), msg->line, msg->len);
    tasvir_log_write(msg->addr, msg->len);
    if (!ttls.thread)
        tasvir_mov32blocks_stream(msg->addr, msg->line, msg->len);
    rte_mempool_put(ttls.nstate->mp, (void *)msg);
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
        tasvir_service_msg_mem((tasvir_msg_mem *)msg);
    } else {
        TASVIR_LOG("received an unrecognized message type %d\n", msg->type);
    }
}

static void tasvir_service_port() {
    tasvir_msg *msg[TASVIR_RING_SIZE];
    unsigned int count, i, retval;

    while ((count = rte_eth_rx_burst(ttls.nstate->port_id, 0, (struct rte_mbuf **)msg, TASVIR_RING_SIZE)) > 0) {
        for (i = 0; i < count; i++) {
            tasvir_service_msg(msg[i]);
        }
    }

    while ((count = rte_ring_sc_dequeue_burst(ttls.nstate->ring_ext_tx, (void **)msg, TASVIR_RING_SIZE, NULL)) > 0) {
        for (i = 0; i < count; i++) {
            struct ether_hdr *eh = &msg[i]->eh;
            ether_addr_copy(&msg[i]->dst_tid.nid.mac_addr, &eh->d_addr);
            ether_addr_copy(&ttls.nstate->mac_addr, &eh->s_addr);
            eh->ether_type = rte_cpu_to_be_16(TASVIR_ETH_PROTO);
        }

        i = 0;
        do {
            retval = rte_eth_tx_burst(ttls.nstate->port_id, 0, (struct rte_mbuf **)&msg[i], count - i);
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
    if (d->immediate && tasvir_is_thread_local(d->owner))
        return;

    tasvir_area_header *h = tasvir_is_owner(d) ? d->h : tasvir_data2shadow(d->h);
    if (!h->active)
        return;

    size_t len = tasvir_size_loggable(d);
    size_t len_this = 0;
    size_t offset = 0;

    while (len > 0) {
        if (ttls.nstate->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
            TASVIR_LOG("more jobs than free slots\n");
            abort();
        }
        len_this = TASVIR_MIN(len, TASVIR_SYNC_JOB_BYTES);
        tasvir_sync_job *j = &ttls.nstate->jobs[ttls.nstate->nr_jobs];
        j->d = d;
        j->offset = offset;
        j->len = len_this;
        j->old_version = h->version;
        j->bytes_changed = 0;

        ttls.nstate->nr_jobs++;
        offset += len_this;
        len -= len_this;
    }
}

static inline void tasvir_walk_areas(tasvir_area_desc *d, tasvir_area_desc_cb_fnptr fnptr) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_container c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_walk_areas(&c[i], fnptr);
    }
    if (d->active)
        fnptr(d);
}

// FIXME: expects len to be aligned
static inline size_t tasvir_sync_job_helper_copy(uint8_t *src, tasvir_log_t *log_internal, size_t len, bool is_owner) {
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
                if (nbits1 > 0)
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
            if (log_internal) {
                *log_internal |= *log;
                log_internal++;
            }
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
    bool is_local = tasvir_is_thread_local(j->d->owner);
    bool is_owner = tasvir_is_owner(j->d);
    tasvir_area_header *h = is_owner ? j->d->h : tasvir_data2shadow(j->d->h);

    if (!h || !h->active || h->d != j->d)
        abort();

    bytes += tasvir_sync_job_helper_copy((uint8_t *)j->d->h + j->offset,
                                         is_local ? h->diff_log[0].data + (j->offset >> TASVIR_SHIFT_UNIT) : NULL,
                                         j->len, is_owner);

    if (bytes > 0 && is_local) {
        /* race doesn't matter because everyone is trying to update version to the same value */
        tasvir_area_header *h2 = is_owner ? tasvir_data2shadow(j->d->h) : j->d->h;
        tasvir_log_write(&h->version, sizeof(h->update_us) + sizeof(h->update_us));
        h->version = h->diff_log[0].version_end = h2->diff_log[0].version_end = j->old_version + 1;
        h->update_us = h->diff_log[0].ts_last_us = h2->diff_log[0].ts_last_us = ttls.nstate->time_us;
        // FIXME: must change this if version and update_us were not consecutive
        bytes += tasvir_sync_job_helper_copy((uint8_t *)j->d->h, h->diff_log[0].data, j->len, is_owner);
        /* tasvir_memset_stream(tasvir_data2log((uint8_t *)d->h + j->offset), 0, j->len >> TASVIR_SHIFT_BYTE); */
    }

    j->bytes_changed = bytes;
}

static inline void tasvir_service_sync_prepare() {
    if (!ttls.node)
        abort();

    /* heartbeat: declare unresponsive threads dead */
    for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
        if (ttls.node->threads[i].status != TASVIR_THREAD_STATUS_RUNNING)
            continue;
        // FIXME: add crash timeout
        while (ttls.nstate->tstate[i].sync)
            rte_delay_us_block(1);
        /*
        // FIXME
        if (ttls.nstate->time_us - ttls.nstate->tstate[i].update_us > ttls.node->heartbeat_us) {
            TASVIR_LOG("thread %d has been inactive for %dms\n", i,
                       ttls.nstate->time_us - ttls.nstate->tstate[i].update_us);
            tasvir_kill_thread(&ttls.node->threads[i]);
        }
        */
    }
    atomic_store(&ttls.nstate->barrier_entry, ttls.node ? ttls.node->nr_threads : 1);
    atomic_store(&ttls.nstate->barrier_exit, ttls.node ? ttls.node->nr_threads : 1);

    ttls.nstate->nr_jobs = 0;
    atomic_store(&ttls.nstate->cur_job, 0);
    tasvir_walk_areas(ttls.root_desc, &tasvir_schedule_sync);

    for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
        if (ttls.node->threads[i].status != TASVIR_THREAD_STATUS_RUNNING)
            continue;
        ttls.nstate->tstate[i].sync = true;
    }
}

static inline void tasvir_service_sync_rotate_logs(tasvir_area_desc *d) {
    if (!d->active)
        return;

    int i;
    const uint64_t MS = 1000;
    uint64_t delta_us[3] = {500 * MS, 15000 * MS, 30000 * MS};
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

    if (rte_mempool_get_bulk(ttls.nstate->mp, (void **)msg, batch_size)) {
        TASVIR_LOG("rte_mempool_get_bulk failed\n");
        // TODO: flush egress and retry
        abort();
    }

    while (len > 0) {
        m = msg[i];
        m->h.src_tid = ttls.thread->tid;
        m->h.dst_tid = ttls.nstate->update_tid;
        m->h.id = ttls.nr_msgs++;
        m->h.type = TASVIR_MSG_TYPE_MEM;
        m->h.time_us = ttls.nstate->time_us;
        m->addr = addr;
        m->len = TASVIR_MIN(TASVIR_CACHELINE_BYTES * TASVIR_NR_CACHELINES_PER_MSG, len);
        m->h.mbuf.pkt_len = m->h.mbuf.data_len = m->len + offsetof(tasvir_msg_mem, line) - offsetof(tasvir_msg, eh);
        tasvir_mov32blocks_stream(m->line, is_owner ? tasvir_data2shadow(addr) : addr, m->len);

        addr = (uint8_t *)addr + m->len;
        len -= m->len;

        if (++i >= batch_size) {
            i = 0;
            if (rte_ring_sp_enqueue_bulk(ttls.nstate->ring_ext_tx, (void **)msg, batch_size, NULL) != batch_size) {
                TASVIR_LOG("rte_ring_sp_enqueue_bulk failed\n");
                // TODO: flush egress and retry
                abort();
            }
            tasvir_service_port();
            if (rte_mempool_get_bulk(ttls.nstate->mp, (void **)msg, batch_size)) {
                TASVIR_LOG("rte_mempool_get_bulk failed\n");
                // TODO: flush egress and retry
                abort();
            }
        }
    }

    size_t count = 0;
    if (i > 0) {
        count = rte_ring_sp_enqueue_bulk(ttls.nstate->ring_ext_tx, (void **)msg, i, NULL);
        if (count != i) {
            TASVIR_LOG("rte_ring_sp_enqueue_bulk failed\n");
            // TODO: flush egress and retry
            abort();
        }
        tasvir_service_port();
        rte_mempool_put_bulk(ttls.nstate->mp, (void **)&msg[i], batch_size - i);
    }
}

static inline size_t tasvir_sync_area_external_boot(tasvir_area_desc *d, bool boot) {
    if (!d || !d->owner || !tasvir_is_thread_local(d->owner) || d->h->diff_log[0].version_end == 0) {
        return 0;
    }

    int i;
    bool is_owner = tasvir_is_owner(d);

    if (!d->pd && ttls.is_root)
        tasvir_msg_mem_generate(d, TASVIR_ALIGNX(sizeof(tasvir_area_desc), TASVIR_CACHELINE_BYTES), true);

    size_t nbits0 = 0;
    size_t nbits1 = 0;
    size_t nbits1_seen = 0;
    size_t nbits_seen = 0;
    size_t nbits_total = tasvir_size_loggable(d) >> TASVIR_SHIFT_BIT;
    uint8_t nbits_same;
    uint8_t nbits_unit_left = TASVIR_MIN(TASVIR_LOG_UNIT_BITS, nbits_total);

    uint8_t *src = (uint8_t *)d->h;
    int pivot = 0;
    tasvir_log_t *log[TASVIR_NR_AREA_LOGS];
    tasvir_log_t log_val = 0;

    // FIXME: latter is a heuristic for boot time
    bool force = boot || ttls.nstate->time_us - ttls.node_desc->boot_us < 5000 * 1000;

    for (pivot = 0; pivot < TASVIR_NR_AREA_LOGS; pivot++) {
        if (!force && ttls.nstate->time_us - d->h->diff_log[pivot].ts_last_us > TASVIR_SYNC_EXTERNAL_US) {
            break;
        }
        log[pivot] = is_owner ? d->h->diff_log[pivot].data : tasvir_data2shadow(d->h->diff_log[pivot].data);
        log_val |= *log[pivot];
    }

    if (pivot == 0)
        return 0;

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

    return nbits1_seen << TASVIR_SHIFT_BIT;
}

static inline size_t tasvir_sync_area_external(tasvir_area_desc *d) { return tasvir_sync_area_external_boot(d, false); }

static inline void tasvir_sync_external() {
    ttls.nstate->last_sync_ext_start = ttls.nstate->time_us;

    tasvir_walk_areas(ttls.root_desc, &tasvir_sync_area_external);

    ttls.nstate->time_us = tasvir_gettime_us();
    ttls.nstate->last_sync_ext_end = ttls.nstate->time_us;
}

static inline int tasvir_service_sync() {
    tasvir_local_tstate *tstate = &ttls.nstate->tstate[ttls.thread->tid.idx];
    if (ttls.is_daemon)
        ttls.nstate->last_sync_start = tstate->update_us;

    size_t cur_job;
    uint64_t time_us = ttls.nstate->time_us;
    size_t total_bytes = 0;

    if (tasvir_barrier_wait(&ttls.nstate->barrier_entry, TASVIR_BARRIER_ENTER_US) != 0) {
        tstate->sync = false;
        return -1;
    }

    while ((cur_job = atomic_fetch_add(&ttls.nstate->cur_job, 1)) < ttls.nstate->nr_jobs) {
        tasvir_sync_job_run(&ttls.nstate->jobs[cur_job]);
        total_bytes += ttls.nstate->jobs[cur_job].bytes_changed;
    }

    /* special case for syncing root desc because it is an orphan */
    if (ttls.is_daemon) {
        /* FIXME: what if root is external? check address mapping when d owner is external */
        /* FIXME: no internal log to capture root desc changes? */
        total_bytes = tasvir_sync_job_helper_copy(
            (uint8_t *)ttls.root_desc, NULL, TASVIR_ALIGN(sizeof(tasvir_area_desc)), tasvir_is_owner(ttls.root_desc));
        ttls.nstate->sync_req = false;
    }

    _mm_sfence();

    if (tasvir_barrier_wait(&ttls.nstate->barrier_exit, TASVIR_HEARTBEAT_US) != 0) {
        tstate->sync = false;
        // FIXME TODO: a thread must have died. loop and diagnose
        TASVIR_LOG("tasvir_barrier_wait exit failed\n");
        return -1;
    }

    tstate->update_us = tasvir_gettime_us();
    tstate->sync = false;

    if (ttls.is_daemon) {
        for (cur_job = 0; cur_job < ttls.nstate->nr_jobs; cur_job++) {
            ttls.nstate->sync_stats_cur.cumbytes += ttls.nstate->jobs[cur_job].bytes_changed;
        }
        ttls.nstate->time_us = tstate->update_us;
        ttls.nstate->last_sync_end = tstate->update_us;
        ttls.nstate->sync_stats_cur.count++;
        ttls.nstate->sync_stats_cur.cumtime_us += tstate->update_us - time_us;

        tasvir_walk_areas(ttls.root_desc, &tasvir_service_sync_rotate_logs);
    }

    return 0;
}

tasvir_sync_stats tasvir_sync_stats_get() { return ttls.nstate->sync_stats; }

void tasvir_sync_stats_reset() {
    memset(&ttls.nstate->sync_stats, 0, sizeof(tasvir_sync_stats));
    memset(&ttls.nstate->sync_stats_cur, 0, sizeof(tasvir_sync_stats));
}

static inline void tasvir_print_area(tasvir_area_desc *d) {
    TASVIR_LOG("name=%s owner=%p version=%lu update_us=%lu\n", d->name, (void *)d->owner, d->h ? d->h->version : 0,
               d->h ? d->h->update_us : 0);
}

static inline void tasvir_service_stats() {
    uint64_t MS = 1 * 1000;  // in us
    uint64_t S = MS * 1000;  // in us
    uint64_t interval_us = ttls.nstate->time_us - ttls.nstate->last_stat;
    ttls.nstate->last_stat = ttls.nstate->time_us;

    tasvir_sync_stats *cur = &ttls.nstate->sync_stats_cur;
    tasvir_sync_stats *avg = &ttls.nstate->sync_stats;

    struct rte_eth_stats s;
    rte_eth_stats_get(0, &s);

    TASVIR_LOG(
        "sync=%lu/s sync_t=%.1f%%,%luus/sync change=%luKB/s,%luKB/sync "
        "\n\t\t\t\t"
        "rx=%luKB/s,%luKpps "
        "(ipkts=%lu ibytes=%lu ierr=%lu imiss=%lu inombuf=%lu"
        ",opkts=%lu obytes=%lu oerr=%lu)\n",
        S * cur->count / interval_us, 100. * cur->cumtime_us / interval_us,
        cur->count > 0 ? cur->cumtime_us / cur->count : 0, MS * cur->cumbytes / interval_us,
        cur->count > 0 ? cur->cumbytes / 1000 / cur->count : 0, MS * cur->cumbytes_rx / interval_us,
        MS * cur->cumpkts_rx / interval_us, s.ipackets, s.ibytes, s.ierrors, s.imissed, s.rx_nombuf, s.opackets,
        s.obytes, s.oerrors);

    avg->count += cur->count;
    avg->cumtime_us += cur->cumtime_us;
    avg->cumbytes += cur->cumbytes;
    avg->cumbytes_rx += cur->cumbytes_rx;
    avg->cumpkts_rx += cur->cumpkts_rx;

    cur->count = 0;
    cur->cumtime_us = 0;
    cur->cumbytes = 0;
    cur->cumbytes_rx = 0;
    cur->cumpkts_rx = 0;
    // tasvir_walk_areas(ttls.root_desc, &tasvir_print_area);
}

static inline void tasvir_service_daemon() {
    /* update time */
    ttls.nstate->time_us = tasvir_gettime_us();
    ttls.nstate->tstate[TASVIR_THREAD_DAEMON_IDX].update_us = ttls.nstate->time_us;

    /* service rings */
    if (ttls.node) {
        for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++)
            if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING ||
                ttls.node->threads[i].status == TASVIR_THREAD_STATUS_BOOTING)
                tasvir_service_ring(ttls.nstate->tstate[i].ring_tx);
    }

    /* service physical port */
    tasvir_service_port();

    if (ttls.thread && ttls.thread->status == TASVIR_THREAD_STATUS_RUNNING) {
        if (ttls.nstate->time_us - ttls.nstate->last_sync_ext_start < TASVIR_SYNC_EXTERNAL_US) {
            /* tasvir_sync_external(); */
        }

        if (ttls.nstate->sync_req || ttls.nstate->time_us - ttls.nstate->last_sync_start >= TASVIR_SYNC_INTERNAL_US) {
            tasvir_service_sync_prepare();
        }

        if (ttls.nstate->time_us - ttls.nstate->last_stat >= TASVIR_STAT_US) {
            tasvir_service_stats();
        }
    }
}

bool tasvir_service() {
    if (ttls.is_daemon)
        tasvir_service_daemon();
    else if (ttls.thread) {
        ttls.nstate->tstate[ttls.thread->tid.idx].update_us = ttls.nstate->time_us;
        tasvir_service_ring(ttls.nstate->tstate[ttls.thread->tid.idx].ring_rx);
    } else
        tasvir_service_ring(ttls.nstate->tstate[TASVIR_THREAD_DAEMON_IDX].ring_rx);

    if (ttls.thread && ttls.nstate->tstate[ttls.thread->tid.idx].sync) {
        return tasvir_service_sync() == 0;
    }

    return false;
}

void tasvir_service_block() {
    while (!tasvir_service()) {
        rte_delay_us_block(1);
        ttls.nstate->sync_req = true;
    }
}
