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

typedef struct tasvir_local_tdata tasvir_local_tdata;
typedef struct tasvir_local_ndata tasvir_local_ndata;
typedef struct tasvir_sync_job tasvir_sync_job;
typedef struct tasvir_tls_data tasvir_tls_data;
typedef enum {
    TASVIR_THREAD_STATE_INVALID = 0,
    TASVIR_THREAD_STATE_DEAD,
    TASVIR_THREAD_STATE_BOOTING,
    TASVIR_THREAD_STATE_RUNNING
} tasvir_thread_state;

static const char *tasvir_thread_state_str[] = {"invalid", "dead", "booting", "running"};

typedef enum {
    TASVIR_MSG_SRC_INVALID = 0,
    TASVIR_MSG_SRC_ME = 1,
    TASVIR_MSG_SRC_LOCAL = 2,
    TASVIR_MSG_SRC_NET2US = 3,
    TASVIR_MSG_SRC_NET2ROOT = 4,
} tasvir_msg_src;

static const char *tasvir_msg_src_str[] = {"invalid", "me", "local", "net2us", "net2root"};

struct tasvir_local_tdata { /* thread data */
    uint64_t update_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    tasvir_thread_state state;
    bool do_sync; /* only updated by daemon */
    bool in_sync; /* only updated by thread */
} __attribute__((aligned(8)));

struct tasvir_sync_job {
    tasvir_area_desc *d;
    atomic_size_t offset;
    atomic_size_t bytes_seen;
    atomic_size_t bytes_updated;
    bool done __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
} __attribute__((aligned(TASVIR_CACHELINE_BYTES)));

struct tasvir_local_ndata { /* node data */
    uint64_t time_us;
    uint64_t sync_int_us;
    uint64_t sync_ext_us;
    uint64_t job_bytes;
    double tsc2usec_mult;
    struct rte_mempool *mp;
    atomic_int barrier_entry;
    pthread_mutex_t mutex_boot;
    struct rte_ring *ring_ext_tx;

    /* daemon data */
    struct ether_addr mac_addr;
    uint8_t port_id;

    tasvir_tid update_tid;
    tasvir_tid rootcast_tid;
    tasvir_tid nodecast_tid;

    /* sync stats */
    uint64_t last_stat;
    uint64_t last_sync_start;
    uint64_t last_sync_end;
    uint64_t last_sync_ext_start;
    uint64_t last_sync_ext_end;
    tasvir_sync_stats sync_stats_cur;
    tasvir_sync_stats sync_stats;

    size_t nr_jobs;
    tasvir_sync_job jobs[TASVIR_NR_SYNC_JOBS];

    bool sync_req;

    /* thread data */
    tasvir_local_tdata tdata[TASVIR_NR_THREADS_LOCAL];
} __attribute__((aligned(8)));

struct tasvir_tls_data { /* thread-internal data */
    tasvir_area_desc *node_desc;
    tasvir_area_desc *root_desc;

    tasvir_local_ndata *ndata;
    tasvir_local_tdata *tdata; /* this thread's tdata */
    tasvir_node *node;
    tasvir_thread *thread;

    uint64_t tsc;

    bool is_root;
    bool is_daemon;
    uint16_t nr_msgs;
    int fd;
    int nr_fns;
    tasvir_fn_info fn_infos[TASVIR_NR_FN];
    tasvir_fn_info *ht_fid;
    tasvir_fn_info *ht_fnptr;
    tasvir_rpc_status status_l[TASVIR_NR_RPC_MSG];
} ttld; /* tasvir thread-local data */

_Static_assert(sizeof(tasvir_local_ndata) <= TASVIR_SIZE_LOCAL,
               "TASVIR_SIZE_LOCAL smaller than sizeof(tasvir_local_ndata)");

#define MS2US (1000)
#define S2US (1000 * MS2US)

#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"

#define LOG_COLORS(MSG_CLR, FMT, ...)                                                   \
    {                                                                                   \
        fprintf(stderr, GRN "%14.3f " CYN "%-22.22s " MSG_CLR FMT "\n" RESET,           \
                ttld.ndata ? ttld.ndata->time_us / 1000. : 0, __func__, ##__VA_ARGS__); \
    }

#ifdef __AVX512F__
#define TASVIR_VEC_UNIT 64
#elif __AVX2__
#define TASVIR_VEC_UNIT 32
#else
#error Tasvir requires AVX2 or AVX512 support
#endif

#ifndef TASVIR_LOG_LEVEL
#define TASVIR_LOG_LEVEL 7
#endif

#if TASVIR_LOG_LEVEL >= 7
#define TASVIR_DEBUG
#define LOG_DBG(FMT, ...) LOG_COLORS(WHT, FMT, ##__VA_ARGS__)
#else
#define LOG_DBG(FMT, ...) \
    do {                  \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 6
#define LOG_VERBOSE(FMT, ...) LOG_COLORS(WHT, FMT, ##__VA_ARGS__)
#else
#define LOG_VERBOSE(FMT, ...) \
    do {                      \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 4
#define LOG_INFO(FMT, ...) LOG_COLORS(YEL, FMT, ##__VA_ARGS__)
#else
#define LOG_INFO(FMT, ...) \
    do {                   \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 3
#define LOG_WARN(FMT, ...) LOG_COLORS(YEL, FMT, ##__VA_ARGS__)
#else
#define LOG_WARN(FMT, ...) \
    do {                   \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 2
#define LOG_ERR(FMT, ...) LOG_COLORS(RED, FMT, ##__VA_ARGS__)
#else
#define LOG_ERR(FMT, ...) \
    do {                  \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 1
#define LOG_FATAL(FMT, ...) LOG_COLORS(RED, FMT, ##__VA_ARGS__)
#else
#define LOG_FATAL(FMT, ...) \
    do {                    \
    } while (0)
#endif

#define MIN(x, y) (x < y ? x : y)
#define TASVIR_ALIGN_ARG(x) (size_t) TASVIR_ALIGNX(x, sizeof(tasvir_arg_promo_t))

/* function prototypes */

static inline int tasvir_attach_helper(tasvir_area_desc *, tasvir_node *);
static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type);
static inline bool tasvir_init_finish(tasvir_thread *);
static inline int tasvir_service_msg(tasvir_msg *, tasvir_msg_src);
static inline size_t tasvir_sync_area_external_boot(tasvir_area_desc *d, bool boot);

/* rpc helpers */

#define R &((uint8_t *)v)[0]
#define X(i) &((uint8_t *)v)[o[i]]
static bool rpc_tasvir_attach_helper(void *v, ptrdiff_t *o) {
    *(int *)R = tasvir_attach_helper(*(tasvir_area_desc **)X(0), *(tasvir_node **)X(1));
    return *(int *)R == 0;
}

static bool rpc_tasvir_delete(void *v, ptrdiff_t *o) {
    *(int *)R = tasvir_delete(*(tasvir_area_desc **)X(0));
    return *(int *)R == 0;
}

static bool rpc_tasvir_init_thread(void *v, ptrdiff_t *o) {
    *(tasvir_thread **)R = tasvir_init_thread(*(pid_t *)X(0), *(uint16_t *)X(1), *(uint8_t *)X(2));
    return *(tasvir_thread **)R != NULL;
}

static bool rpc_tasvir_init_finish(void *v, ptrdiff_t *o) {
    *(bool *)R = tasvir_init_finish(*(tasvir_thread **)X(0));
    return *(bool *)R;
}

static bool rpc_tasvir_new(void *v, ptrdiff_t *o) {
    *(tasvir_area_desc **)R = tasvir_new(*(tasvir_area_desc *)X(0));
    return *(tasvir_area_desc **)R != NULL;
}

static bool rpc_tasvir_sync_area_external_boot(void *v, ptrdiff_t *o) {
    *(size_t *)R = tasvir_sync_area_external_boot(*(tasvir_area_desc **)X(0), *(bool *)X(1));
    return *(size_t *)R > 0;
}

static bool rpc_tasvir_update_owner(void *v, ptrdiff_t *o) {
    *(bool *)R = tasvir_update_owner(*(tasvir_area_desc **)X(0), *(tasvir_thread **)X(1));
    return *(bool *)R;
}
#undef R
#undef X

/* utils */

static inline uint64_t tasvir_rdtsc() { return rte_rdtsc(); }
static inline uint64_t tasvir_gettime_us() { return ttld.ndata->tsc2usec_mult * tasvir_rdtsc(); }
static inline uint64_t tasvir_tsc2usec(uint64_t tsc) { return ttld.ndata->tsc2usec_mult * tsc; }

__attribute__((unused)) static inline void tasvir_hexdump(void *addr, size_t len) {
    uint8_t *b = (uint8_t *)addr;
    size_t i;
    for (i = 0; i < len; i += 4) {
        if (i && i % 32 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02X%02X%02X%02X ", b[i], b[i + 1], b[i + 2], b[i + 3]);
    }
    fprintf(stderr, "\n");
}

static inline bool tasvir_barrier_wait(atomic_int *count, int64_t timeout_us) {
    uint64_t end_time_us = tasvir_gettime_us() + timeout_us;
    int val = atomic_fetch_sub(count, 1) - 1;
    while (tasvir_gettime_us() < end_time_us && val > 0) {
        rte_delay_us_block(1);
        val = atomic_load(count);
    }

    /* ensure output is either 0 or -1 */
    while (val > 0 && !atomic_compare_exchange_weak(count, &val, -1))
        val = atomic_load(count);

    return val == 0;
}

static inline bool tasvir_is_attached(const tasvir_area_desc *d, const tasvir_node *node) {
    if (d->h && d->h->active) {
        if (!node)
            return true;
        for (size_t i = 0; i < d->h->nr_users; i++)
            if (d->h->users[i].node == node)
                return true;
    }
    return false;
}

static inline bool tasvir_is_owner(const tasvir_area_desc *d) {
    if (!d) { /* assume called on root's pd */
        return ttld.is_root;
    } else if (!d->pd) { /* root area */
        return ttld.is_root;
    } else if (!ttld.thread) { /* preboot: node area, only daemon should ever reach here */
        return ttld.is_daemon;
    } else if (!d->owner) { /* FIXME: am I missing a corner case? */
        return false;
    } else {
        return d->owner == ttld.thread;
    }
}

/* assumption: d && d->h */
static inline bool tasvir_is_mapped_rw(const tasvir_area_desc *d) { return d->h->private_tag.rw; }

static inline bool tasvir_is_local(const tasvir_area_desc *d) { return d->h->private_tag.local; }

static inline bool tasvir_is_thread_local(tasvir_thread *t) {
    return memcmp(&t->tid.nid, &ttld.ndata->nodecast_tid.nid, sizeof(tasvir_nid)) == 0;
}

static inline void tasvir_tid2str(tasvir_tid tid, size_t buf_size, char *buf) {
    ether_format_addr(buf, buf_size, &tid.nid.mac_addr);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), ":%d", tid.idx);
}

static inline void tasvir_mov_blocks_stream(void *dst, const void *src, size_t len) {
    while (len > 0) {
#if TASVIR_VEC_UNIT == 64
        __m512i m = _mm512_stream_load_si512((const __m512i *)src);
        _mm512_stream_si512((__m512i *)dst, m);
#else
        __m256i m = _mm256_stream_load_si256((const __m256i *)src);
        _mm256_stream_si256((__m256i *)dst, m);
#endif
        len -= TASVIR_VEC_UNIT;
        dst = (uint8_t *)dst + TASVIR_VEC_UNIT;
        src = (uint8_t *)src + TASVIR_VEC_UNIT;
    }
}

__attribute__((unused)) static inline void tasvir_memset_stream(void *dst, char c, size_t len) {
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

static inline void tasvir_populate_msg_nethdr(tasvir_msg *m) {
    m->mbuf.refcnt = 1;
    m->mbuf.nb_segs = 1;
    ether_addr_copy(&m->dst_tid.nid.mac_addr, &m->eh.d_addr);
    ether_addr_copy(&ttld.ndata->mac_addr, &m->eh.s_addr);
    m->eh.ether_type = rte_cpu_to_be_16(TASVIR_ETH_PROTO);

    // FIXME: not all will be sent out
    ttld.ndata->sync_stats_cur.cumbytes_tx += m->mbuf.pkt_len;
    ttld.ndata->sync_stats_cur.cumpkts_tx++;
}

__attribute__((unused)) static inline void tasvir_print_area(tasvir_area_desc *d) {
    LOG_DBG("name=%s owner=%p version=%lu update_us=%lu", d->name, (void *)d->owner, d->h ? d->h->version : 0,
            d->h ? d->h->update_us : 0);
}

static inline void tasvir_print_msg(tasvir_msg *m, bool is_src_me, bool is_dst_me) {
    tasvir_str src_str, dst_str;
    char direction;
    tasvir_tid2str(m->src_tid, sizeof(src_str), src_str);
    tasvir_tid2str(m->dst_tid, sizeof(dst_str), dst_str);
    if (is_src_me)
        direction = 'O';
    else if (is_dst_me)
        direction = 'I';
    else
        direction = 'F';
    if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE || m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_msg_rpc *mr = (tasvir_msg_rpc *)m;
        tasvir_fn_info *fni;
        HASH_FIND(h_fid, ttld.ht_fid, &mr->fid, sizeof(mr->fid), fni);

        LOG_DBG("%c %s->%s id=%d type=%s desc=%s f=%s", direction, src_str, dst_str, m->id,
                tasvir_msg_type_str[m->type], mr->d ? mr->d->name : "root", fni->name);
    } else {
        LOG_DBG("%c %s->%s id=%d type=%s", direction, src_str, dst_str, m->id, tasvir_msg_type_str[m->type]);
    }
    // tasvir_hexdump(&m->h.eh, m->h.mbuf.data_len);
}

static inline void tasvir_update_va(const tasvir_area_desc *d, bool is_rw) {
    void *ret;
    void *data = (uint8_t *)d->h;
    void *shadow = tasvir_data2shadow(d->h);
    ptrdiff_t data_offset = (uint8_t *)data - (uint8_t *)TASVIR_ADDR_BASE;
    ptrdiff_t shadow_offset = (uint8_t *)shadow - (uint8_t *)TASVIR_ADDR_BASE;
    ret = mmap(data, d->offset_log_end, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttld.fd,
               is_rw ? shadow_offset : data_offset);
    if (ret != data) {
        LOG_ERR("mmap for working area failed (request=%p return=%p)", data, ret);
        abort();
    }
    ret = mmap(shadow, d->offset_log_end, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttld.fd,
               is_rw ? data_offset : shadow_offset);
    if (ret != shadow) {
        LOG_ERR("mmap for scratch area failed (request=%p return=%p)", shadow, ret);
        abort();
    }

    /* FIXME: not the best place to update these tags */
    d->h->private_tag.rw = is_rw;
    ((tasvir_area_header *)shadow)->private_tag.rw = !is_rw;
}

static inline void tasvir_walk_areas(tasvir_area_desc *d, tasvir_area_desc_cb_fnptr fnptr) {
    if (!d->active)
        return;
    fnptr(d);
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++) {
            tasvir_walk_areas(&c[i], fnptr);
        }
    }
}

/* initializtion */

static inline void tasvir_init_rpc() {
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_init_thread,
        .name = "tasvir_init_thread",
        .oneway = 0,
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
        .oneway = 0,
        .fid = 3,
        .argc = 1,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_init_finish,
        .name = "tasvir_init_finish",
        .oneway = 0,
        .fid = 4,
        .argc = 1,
        .ret_len = sizeof(bool),
        .arg_lens = {sizeof(tasvir_thread *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_update_owner,
        .name = "tasvir_update_owner",
        .oneway = 0,
        .fid = 5,
        .argc = 2,
        .ret_len = sizeof(bool),
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_thread *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_attach_helper,
        .name = "tasvir_attach_helper",
        .oneway = 0,
        .fid = 6,
        .argc = 2,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_node *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &rpc_tasvir_sync_area_external_boot,
        .name = "tasvir_sync_area_external_boot",
        .oneway = 0,
        .fid = 7,
        .argc = 2,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(bool)},
    });
}

static inline int tasvir_init_dpdk(uint16_t core, char *pciaddr) {
    int argc = 0, retval;
    char *argv[64];
    tasvir_str core_str;
    // tasvir_str mem_str;
    tasvir_str base_virtaddr;
    snprintf(core_str, sizeof(core_str), "%d", core);
    // snprintf(mem_str, sizeof(mem_str), "512,512");
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
    // argv[argc++] = "--socket-mem";
    // argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
    argv[argc++] = ttld.is_daemon ? "primary" : "secondary";
    if (pciaddr) {
        if (strncmp("net_bonding", pciaddr, 11) == 0) {
            argv[argc++] = "--vdev";
            argv[argc++] = pciaddr;
        } else {
            argv[argc++] = "--pci-whitelist";
            argv[argc++] = pciaddr;
        }
    }
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        LOG_ERR("rte_eal_init failed");
        return -1;
    }
    return 0;
}

static int tasvir_init_port(char *pciaddr) {
    tasvir_str port_name;
    if (!ttld.is_daemon || !pciaddr)
        return 0;

    int nb_ports = rte_eth_dev_count();
    if (nb_ports == 0) {
        LOG_ERR("rte_eth_dev_count() == 0");
        return -1;
    }

    strncpy(port_name, pciaddr, sizeof(port_name));
    if (strncmp("net_bonding", pciaddr, 11) == 0) {
        char *s = strchr(port_name, ',');
        if (s)
            *s = '\0';
    }

    if (rte_eth_dev_get_port_by_name(port_name, &ttld.ndata->port_id) != 0) {
        LOG_ERR("rte_eth_dev_get_port_by_name() failed, name=%s", port_name);
        return -1;
    }
    rte_eth_macaddr_get(ttld.ndata->port_id, &ttld.ndata->mac_addr);
    ether_addr_copy(&ttld.ndata->mac_addr, &ttld.ndata->nodecast_tid.nid.mac_addr);

    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf *rx_conf;
    struct rte_eth_txconf *tx_conf;
    struct rte_eth_link link;
    uint64_t end_time_us;
    int retval;

    /* prepare configs */
    memset(&port_conf, 0, sizeof(port_conf));
    rte_eth_dev_info_get(ttld.ndata->port_id, &dev_info);
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

    retval = rte_eth_dev_configure(ttld.ndata->port_id, 1, 1, &port_conf);
    if (retval < 0) {
        LOG_ERR("Cannot configure device: err=%d, port=%d", retval, ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_rx_queue_setup(ttld.ndata->port_id, 0, TASVIR_RING_EXT_SIZE,
                                    rte_eth_dev_socket_id(ttld.ndata->port_id), rx_conf, ttld.ndata->mp);
    if (retval < 0) {
        LOG_ERR("rte_eth_rx_queue_setup:err=%d, port=%u", retval, (unsigned)ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_tx_queue_setup(ttld.ndata->port_id, 0, TASVIR_RING_EXT_SIZE,
                                    rte_eth_dev_socket_id(ttld.ndata->port_id), tx_conf);
    if (retval < 0) {
        LOG_ERR("rte_eth_tx_queue_setup:err=%d, port=%u", retval, (unsigned)ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_dev_start(ttld.ndata->port_id);
    if (retval < 0) {
        LOG_ERR("rte_eth_dev_start: err=%d, port=%u", retval, ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_dev_set_link_up(ttld.ndata->port_id);
    if (retval < 0) {
        LOG_ERR("rte_eth_dev_set_link_up: err=%d, port=%u", retval, ttld.ndata->port_id);
        // return -1;
    }

    end_time_us = tasvir_gettime_us() + 3 * S2US;
    do {
        rte_eth_link_get(ttld.ndata->port_id, &link);
    } while (tasvir_gettime_us() < end_time_us && link.link_status != ETH_LINK_UP);

    if (link.link_status != ETH_LINK_UP) {
        LOG_ERR("rte_eth_link_get_nowait: link is down port=%u", ttld.ndata->port_id);
        return -1;
    }

    rte_eth_promiscuous_enable(ttld.ndata->port_id);
    rte_eth_stats_reset(ttld.ndata->port_id);
    rte_eth_xstats_reset(ttld.ndata->port_id);

    tasvir_str buf;
    ether_format_addr(buf, sizeof(buf), &ttld.ndata->mac_addr);
    LOG_INFO("port=%d mac=%s", ttld.ndata->port_id, buf);

    return 0;
}

static int tasvir_init_local() {
    void *base;
    int shm_oflag = ttld.is_daemon ? O_CREAT | O_EXCL | O_RDWR : O_RDWR;
    mode_t shm_mode = ttld.is_daemon ? S_IRUSR | S_IWUSR : 0;
    ptrdiff_t size_whole = TASVIR_ADDR_END - TASVIR_ADDR_BASE;

    ttld.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttld.fd == -1)
        return -1;
    if (ftruncate(ttld.fd, size_whole)) {
        LOG_ERR("ftruncate failed (%s)", strerror(errno));
        return -1;
    }
    base = mmap((void *)TASVIR_ADDR_BASE, size_whole, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttld.fd, 0);
    if (base != (void *)TASVIR_ADDR_BASE) {
        LOG_ERR("mmap failed");
        return -1;
    }

    ttld.ndata = (void *)TASVIR_ADDR_LOCAL;
    ttld.tdata = &ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX];

    if (ttld.is_daemon) {
        memset(ttld.ndata, 0, sizeof(tasvir_local_ndata));
        /* boot mutex */
        pthread_mutexattr_t mutex_attr;
        pthread_mutexattr_init(&mutex_attr);
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ttld.ndata->mutex_boot, &mutex_attr);
        pthread_mutexattr_destroy(&mutex_attr);
        atomic_store(&ttld.ndata->barrier_entry, -1);

        /* mempool */
        ttld.ndata->mp =
            rte_pktmbuf_pool_create("mempool", 128 * 1024 - 1, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!ttld.ndata->mp) {
            LOG_ERR("failed to create pkt mempool");
            return -1;
        }

        /* tx ring */
        ttld.ndata->ring_ext_tx =
            rte_ring_create("tasvir_ext_tx", TASVIR_RING_EXT_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        LOG_DBG("created ring for external tx %p", (void *)ttld.ndata->ring_ext_tx);
        if (ttld.ndata->ring_ext_tx == NULL) {
            LOG_ERR("failed to create external rings");
            return -1;
        }

        /* timing */
        ttld.ndata->sync_int_us = TASVIR_SYNC_INTERNAL_US;
        ttld.ndata->sync_ext_us = TASVIR_SYNC_EXTERNAL_US;
        ttld.ndata->tsc2usec_mult = 1E6 / rte_get_tsc_hz();

        /* ids */
        ttld.ndata->update_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0xff}}};
        ttld.ndata->update_tid.idx = -1;
        ttld.ndata->update_tid.pid = -1;
        ttld.ndata->rootcast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}}};
        ttld.ndata->rootcast_tid.idx = -1;
        ttld.ndata->rootcast_tid.pid = -1;
        ttld.ndata->nodecast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x02}}};
        ttld.ndata->nodecast_tid.idx = -1;
        ttld.ndata->nodecast_tid.pid = -1;
    } else {
        /* wait for 15s for the daemon to boot */
        uint64_t end_time_us = tasvir_gettime_us() + 15 * S2US;
        while (tasvir_gettime_us() < end_time_us && ttld.tdata->state != TASVIR_THREAD_STATE_RUNNING) {
            rte_delay_ms(1);
        }
        if (ttld.tdata->state != TASVIR_THREAD_STATE_RUNNING) {
            LOG_ERR("daemon not initialized");
            return -1;
        }
    }

    return 0;
}

static int tasvir_init_root() {
    ttld.root_desc = (tasvir_area_desc *)TASVIR_ADDR_ROOT_DESC;
    tasvir_area_desc *d_ret;

    if (ttld.is_root) {
        d_ret = tasvir_new((tasvir_area_desc){.pd = NULL,
                                              .owner = NULL,
                                              .type = TASVIR_AREA_TYPE_CONTAINER,
                                              .name = "root",
                                              .len = TASVIR_SIZE_DATA - 2 * TASVIR_HUGEPAGE_SIZE,
                                              .nr_areas_max = TASVIR_NR_AREAS_MAX});
    } else {
        d_ret = tasvir_attach_wait(NULL, "root", NULL, false, 15 * S2US);
    }

    if (!d_ret || !d_ret->active) {
        LOG_ERR("root not initialized")
        return -1;
    } else if (d_ret != ttld.root_desc) {
        LOG_ERR("returned address doesn't match root_desc address")
        return -1;
    }

    return 0;
}

static int tasvir_init_node() {
    /* FIXME: assuming a clean boot */
    tasvir_str name = "node-";
    ether_format_addr(&name[strlen(name)], sizeof(name) - strlen(name), &ttld.ndata->mac_addr);

    if (ttld.is_daemon) {
        /* id and address */
        /* initializing boot_us so that could be later use this node's clock rather than root's */
        ttld.node_desc = tasvir_new((tasvir_area_desc){.pd = ttld.root_desc,
                                                       .owner = NULL,
                                                       .type = TASVIR_AREA_TYPE_NODE,
                                                       .name_static = *(tasvir_str_static *)name,
                                                       .len = sizeof(tasvir_node),
                                                       .nr_areas_max = 0,
                                                       .boot_us = tasvir_gettime_us()});
        if (!ttld.node_desc) {
            LOG_ERR("failed to allocate node");
            return -1;
        }
        ttld.node = tasvir_data(ttld.node_desc);
        memset(ttld.node, 0, sizeof(tasvir_node));
        ether_addr_copy(&ttld.ndata->mac_addr, &ttld.node->nid.mac_addr);
        ttld.node->heartbeat_us = TASVIR_HEARTBEAT_US;

        /* time */
        tasvir_log_write(ttld.node, sizeof(tasvir_node));
    } else {
        ttld.node_desc = tasvir_attach_wait(ttld.root_desc, name, NULL, false, 500 * MS2US);
        if (!ttld.node_desc || !ttld.node_desc->h->active) {
            LOG_ERR("node not initiliazed yet");
            return -1;
        }
        ttld.node = tasvir_data(ttld.node_desc);

        tasvir_local_tdata *daemon_tdata = &ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX];

        /* daemon alive? */
        uint64_t time_us = tasvir_gettime_us();
        if (!ttld.node_desc->active) {
            LOG_ERR("daemon is inactive");
            return -1;
        } else if (time_us > daemon_tdata->update_us &&
                   time_us - daemon_tdata->update_us > ttld.node_desc->sync_int_us) {
            LOG_ERR("daemon has been stale for %lu us (> %lu), last activity %lu",
                    time_us - ttld.node_desc->h->update_us, ttld.node_desc->sync_int_us, ttld.node_desc->h->update_us);
            return -1;
        }
    }

    return 0;
}

static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type) {
    tasvir_thread *t = NULL;

    if (ttld.is_daemon) {
        /* find a free thread id */
        uint16_t tid;
        for (tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
            if (ttld.ndata->tdata[tid].state != TASVIR_THREAD_STATE_RUNNING &&
                ttld.ndata->tdata[tid].state != TASVIR_THREAD_STATE_BOOTING)
                break;
        }

        if (tid == TASVIR_NR_THREADS_LOCAL)
            return NULL;

        /* populate thread */
        t = &ttld.node->threads[tid];
        t->core = core;
        t->type = type;
        t->tid.nid = ttld.node->nid;
        t->tid.idx = tid;
        t->tid.pid = pid;
        tasvir_log_write(t, sizeof(tasvir_thread));

        tasvir_local_tdata *tdata = &ttld.ndata->tdata[tid];
        tasvir_str tmp;
        /* rings */
        sprintf(tmp, "tasvir_tx_%d", tid);
        tdata->ring_tx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        sprintf(tmp, "tasvir_rx_%d", tid);
        tdata->ring_rx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        LOG_DBG("created rings tx=%p rx=%p for tid=%d", (void *)tdata->ring_tx, (void *)tdata->ring_rx, tid);
        if (tdata->ring_tx == NULL || tdata->ring_rx == NULL) {
            LOG_ERR("failed to create rings for tid %d", tid);
            return NULL;
        }
        tdata->state = TASVIR_THREAD_STATE_BOOTING;
    } else {
        /* FIXME: deadlock on crash */
        pthread_mutex_lock(&ttld.ndata->mutex_boot);
        bool retval = tasvir_rpc_wait(S2US, (void **)&t, ttld.node_desc, &rpc_tasvir_init_thread, pid, core, type);
        pthread_mutex_unlock(&ttld.ndata->mutex_boot);
        if (!retval)
            return NULL;
    }

    LOG_INFO("addr=%p tid=%d core=%d pid=%d", (void *)t, t->tid.idx, t->core, t->tid.pid);

    return t;
}

static inline void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c[i]);
    }
    if (d->owner == t)
        tasvir_update_owner(d, ttld.thread);
}

/* caller contract: assert(ttld.is_daemon && tasvir_is_thread_local(t)); */
static inline void tasvir_kill_thread(tasvir_thread *t) {
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
    LOG_INFO("tid=%d inactive_time=%zd", t->tid.idx, ttld.ndata->time_us - tdata->update_us);
    tdata->update_us = 0;
    tdata->do_sync = false;
    tdata->state = TASVIR_THREAD_STATE_DEAD;
    rte_ring_free(tdata->ring_rx);
    rte_ring_free(tdata->ring_tx);
    tdata->ring_rx = NULL;
    tdata->ring_tx = NULL;

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttld.root_desc);

    /* kill by pid */
    kill(t->tid.pid, SIGKILL);

    // FIXME: node_desc must deactivate
    t->active = false;
    tasvir_log_write(&t->active, sizeof(t->active));
}

static inline bool tasvir_init_finish(tasvir_thread *t) {
    if (ttld.ndata->tdata[t->tid.idx].state != TASVIR_THREAD_STATE_BOOTING) {
        LOG_ERR("called from a thread that is not in the BOOTING state");
        return false;
    }

    if (ttld.is_daemon) {
        t->active = true;
        tasvir_log_write(&t->active, sizeof(t->active));

        /* backfill area owners */
        if (t == ttld.thread) {
            if (ttld.is_root) {
                ttld.node_desc->owner = ttld.thread;
                ttld.root_desc->owner = ttld.thread;
                tasvir_log_write(&ttld.node_desc->owner, sizeof(ttld.node_desc->owner));
                tasvir_log_write(&ttld.root_desc->owner, sizeof(ttld.root_desc->owner));
            } else if (!tasvir_update_owner(ttld.node_desc, ttld.thread)) {
                return false;
            }
        }
    } else {
        bool retval;
        // FIXME: retval
        if (!tasvir_rpc_wait(S2US, (void **)&retval, ttld.node_desc, &rpc_tasvir_init_finish, t) || !retval) {
            return false;
        }
    }

    if (t == ttld.thread)
        ttld.tdata->state = TASVIR_THREAD_STATE_RUNNING;

    LOG_INFO("tid=%d core=%d pid=%d", t->tid.idx, t->core, t->tid.pid);
    return true;
}

tasvir_area_desc *tasvir_init(tasvir_thread_type type, uint16_t core, char *pciaddr) {
    assert(!ttld.node && !ttld.thread);

    memset(&ttld, 0, sizeof(tasvir_tls_data));
    ttld.is_daemon = type == TASVIR_THREAD_TYPE_DAEMON || type == TASVIR_THREAD_TYPE_ROOT;
    ttld.is_root = type == TASVIR_THREAD_TYPE_ROOT;

    tasvir_init_rpc();

    LOG_INFO("initializing dpdk");
    if (tasvir_init_dpdk(core, pciaddr)) {
        LOG_ERR("tasvir_init_dpdk failed");
        return NULL;
    }

    LOG_INFO("initializing local control memory");
    if (tasvir_init_local()) {
        LOG_ERR("tasvir_init_local failed");
        return NULL;
    }

    LOG_INFO("initializing network port");
    if (tasvir_init_port(pciaddr)) {
        LOG_ERR("tasvir_init_port failed");
        return NULL;
    }

    LOG_INFO("initializing root area");
    if (tasvir_init_root()) {
        LOG_ERR("tasvir_init_root failed");
        return NULL;
    }

    LOG_INFO("initializing node area");
    if (tasvir_init_node()) {
        LOG_ERR("tasvir_init_node failed");
        return NULL;
    }

    LOG_INFO("initializing thread");
    ttld.thread = tasvir_init_thread(getpid(), core, type);
    if (!ttld.thread) {
        LOG_ERR("tasvir_init_thread failed");
        return NULL;
    }
    ttld.tdata = &ttld.ndata->tdata[ttld.thread->tid.idx];

    LOG_INFO("finializing initialization");
    if (!tasvir_init_finish(ttld.thread)) {
        LOG_ERR("tasvir_init_finish failed");
        return NULL;
    }

    return ttld.root_desc;
}

/* area management */

tasvir_area_desc *tasvir_new(tasvir_area_desc desc) {
    if (!desc.owner && desc.type != TASVIR_AREA_TYPE_NODE)
        desc.owner = ttld.thread;
    if (desc.sync_int_us == 0)
        desc.sync_int_us = TASVIR_SYNC_INTERNAL_US;
    if (desc.sync_ext_us == 0)
        desc.sync_ext_us = TASVIR_SYNC_EXTERNAL_US;

    desc.active = false;
    tasvir_area_desc *d = NULL;
    tasvir_area_desc *c = NULL;
    uint64_t time_us = tasvir_gettime_us();
    bool is_root_area = !desc.pd;
    bool is_desc_owner = tasvir_is_owner(desc.pd);
    bool is_owner = desc.type == TASVIR_AREA_TYPE_NODE ? !ttld.node : tasvir_is_owner(&desc);
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;

    if ((is_container && desc.nr_areas_max == 0) || (!is_container && desc.nr_areas_max != 0)) {
        LOG_ERR("mismatch between type and number of subareas (type=%s,nr_areas_max=%lu)",
                tasvir_area_type_str[desc.type], desc.nr_areas_max);
        return NULL;
    }
    if ((is_root_area && !is_container) || (!is_root_area && desc.pd->type != TASVIR_AREA_TYPE_CONTAINER)) {
        LOG_ERR("incorrect area type");
        return NULL;
    }

    size_t size_metadata = sizeof(tasvir_area_header) + desc.nr_areas_max * sizeof(tasvir_area_desc);
    if (is_owner)
        desc.offset_log_end = TASVIR_ALIGN(size_metadata + !is_container * desc.len);
    size_t offset_log = TASVIR_ALIGN(size_metadata + desc.len);
    size_t size_log = TASVIR_ALIGNX(desc.offset_log_end >> TASVIR_SHIFT_BYTE, sizeof(tasvir_log_t));
    if (is_owner)
        desc.len = offset_log + TASVIR_ALIGN(TASVIR_NR_AREA_LOGS * size_log);

    assert(is_root_area || desc.pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(!is_root_area || is_container);

    /* initialize the area descriptor */
    if (is_desc_owner) {
        void *h = NULL;
        if (is_root_area) {
            d = ttld.root_desc;
            h = (void *)TASVIR_ADDR_DATA;
        } else {
            c = tasvir_data(desc.pd);

            /* ensure enough descriptors */
            if (desc.pd->h->nr_areas >= desc.pd->nr_areas_max) {
                LOG_ERR("out of descriptors");
                return NULL;
            }

            /* ensure area does not exist */
            for (size_t i = 0; i < desc.pd->h->nr_areas; i++) {
                if (strncmp(c[i].name, desc.name, sizeof(tasvir_str)) == 0) {
                    LOG_ERR("area exists");
                    return NULL;
                }
            }

            size_t *nr_areas = &desc.pd->h->nr_areas;
            d = &c[*nr_areas];
            h = (void *)TASVIR_ALIGN((*nr_areas > 0 ? (uint8_t *)c[*nr_areas - 1].h + c[*nr_areas - 1].len
                                                    : (uint8_t *)c + desc.pd->nr_areas_max * sizeof(tasvir_area_desc)));
            if ((uint8_t *)h + desc.len >= (uint8_t *)desc.pd->h->diff_log[0].data) {
                LOG_ERR("out of space");
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
    } else if (!tasvir_rpc_wait(5 * S2US, (void **)&d, desc.pd, &rpc_tasvir_new, desc))
        return NULL;

    /* sanity check */
    if (!d || !d->active || !d->h) {
        LOG_ERR("invalid descriptor: d=%p, d->active=%d, d->h=%p", (void *)d, d ? d->active : false,
                d ? (void *)d->h : NULL);
        return NULL;
    }

    /* initialize the header */
    if (is_owner) {
        tasvir_update_va(d, true);
        memset(d->h, 0, size_metadata);
        d->h->private_tag.rw = true;
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = true;
        d->h->private_tag.external_sync_pending = false;
        d->h->d = d;
        d->h->version = 1;
        d->h->update_us = time_us;
        d->h->nr_areas = 0;
        d->h->nr_users = 1;
        d->h->users[0].node = ttld.node;
        d->h->users[0].version = 0;
        for (size_t i = 0; i < TASVIR_NR_AREA_LOGS; i++) {
            tasvir_area_log *log = &d->h->diff_log[i];
            log->version_start = 0;
            log->version_end = 0;
            log->start_us = time_us;
            log->end_us = 0;
            log->data = (tasvir_log_t *)((uint8_t *)d->h + offset_log + i * size_log);
        }
        d->h->active = true;
        tasvir_log_write(&d->h->d, sizeof(tasvir_area_header) - offsetof(tasvir_area_header, d));
    }

    LOG_INFO(
        "name=%s type=%s len=0x%lx sync_us=%lu/%lu boot_us=%lu nr_areas_max=%lu active=%s "
        "d=%p pd=%p owner=%p h=%p is_desc_owner=%s is_owner=%s is_local=%s",
        d->name, tasvir_area_type_str[d->type], d->len, d->sync_int_us, d->sync_ext_us, d->boot_us, d->nr_areas_max,
        d->active ? "true" : "false", (void *)d, (void *)d->pd, (void *)d->owner, (void *)d->h,
        is_desc_owner ? "true" : "false", is_owner ? "true" : "false", d->h->private_tag.local ? "true" : "false");

    return d;
}

/* asssumption: d && d->pd */
int tasvir_delete(tasvir_area_desc *d) {
    /* TODO: remove from d->pd */
    if (tasvir_is_owner(d->pd)) {
        d->active = false;
        return 0;
    } else {
        int retval = -1;
        if (!tasvir_rpc_wait(S2US, (void **)&retval, d->pd, &rpc_tasvir_delete, d)) {
            return -1;
        }
        return retval;
    }
}

static inline int tasvir_attach_helper(tasvir_area_desc *d, tasvir_node *node) {
    if (tasvir_is_attached(d, node))
        return 0;

    if (tasvir_is_owner(d)) {
        if (d->h->nr_users >= TASVIR_NR_NODES_AREA) {
            LOG_ERR("%s has reached max number of subscribers", d->name);
            return -1;
        }

        if (node) {
            d->h->users[d->h->nr_users].node = node;
            d->h->users[d->h->nr_users].version = 0;
            d->h->nr_users++;
            tasvir_log_write(&d->h->nr_users, sizeof(d->h->nr_users));
            tasvir_log_write(&d->h->users[d->h->nr_users], sizeof(d->h->users[d->h->nr_users]));
        }

        if (ttld.is_daemon) {
            tasvir_sync_area_external_boot(d, true);
        } else {
            tasvir_rpc_status *rs = tasvir_rpc(ttld.node_desc, &rpc_tasvir_sync_area_external_boot, d, true);
            if (rs)
                rs->do_free = true;
        }

        /* FIXME: hack to distribute node and thread info at boot time */
        if (d == ttld.root_desc) {
            tasvir_area_desc *c = tasvir_data(d);
            for (size_t i = 0; i < d->h->nr_areas; i++)
                if (c[i].type == TASVIR_AREA_TYPE_NODE)
                    tasvir_sync_area_external_boot(&c[i], true);
        }
    } else if (d->owner && (d == ttld.root_desc || ttld.thread) &&
               !tasvir_rpc_wait(S2US, NULL, d, &rpc_tasvir_attach_helper, d, node)) {
        return -1;
    }

    if (d == ttld.root_desc && !node)
        return 0;
    return !tasvir_is_attached(d, node);
}

/* TODO: sanity checking? */
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer) {
    tasvir_area_desc *d = NULL;

    if (!pd) /* root_area */
        d = ttld.root_desc;
    else if (pd->active && pd->type == TASVIR_AREA_TYPE_CONTAINER && pd->h && pd->h->active) {
        tasvir_area_desc *c = tasvir_data(pd);
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

    if ((!d->h->active || d == ttld.root_desc) && !tasvir_is_local(d)) {
        if (tasvir_attach_helper(d, node ? node : ttld.node))
            return NULL;
    }

    if (!d->h->active)
        return NULL;

    tasvir_update_va(d, writer);
    LOG_INFO("name=%s len=%lu h=%p", d->name, d->len, (void *)d->h);
    return d;
}

tasvir_area_desc *tasvir_attach_wait(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer,
                                     uint64_t timeout_us) {
    tasvir_area_desc *d;
    uint64_t end_time_us = tasvir_gettime_us() + timeout_us;
    while (tasvir_gettime_us() < end_time_us && !(d = tasvir_attach(pd, name, node, writer))) {
        for (int i = 0; i < 1000; i++) {
            tasvir_service();
            rte_delay_us(1);
        }
    }
    return d;
}

int tasvir_detach(tasvir_area_desc *d) {
    /* TODO: sanity check */
    /* TODO: update subscriber's list */

    return 0;
}

bool tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    tasvir_thread *desc_owner = d->pd ? d->pd->owner : d->owner;
    bool is_new_owner = owner == ttld.thread;
    bool is_old_owner = d->owner == ttld.thread;
    bool is_desc_owner = desc_owner == ttld.thread;

    if (is_new_owner) {
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = true;
        tasvir_update_va(d, true);
        /* FIXME: error reporting and function return value */
        /* FIXME: change to async and wait for change to propagate */

        if (!is_old_owner) {
            /* rpc to previous owner if one exists */
            if (d->owner && !tasvir_rpc_wait(S2US, NULL, d, &rpc_tasvir_update_owner, d, owner))
                return false;

            /* rpc to desc owner if not the same as desc owner (previous call) */
            if (d->pd && !is_desc_owner && !tasvir_rpc_wait(S2US, NULL, d->pd, &rpc_tasvir_update_owner, d, owner))
                return false;
        }
    } else if (is_old_owner) {
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = false;
        /* restore the mappings of the old owner */
        tasvir_update_va(d, false);
    }

    if (is_desc_owner) {
        d->owner = owner;
        tasvir_log_write(&d->owner, sizeof(d->owner));
    }

    return true;
}

/* rpc */

static tasvir_rpc_status *tasvir_vrpc(tasvir_area_desc *d, tasvir_fnptr fnptr, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *m;
    if (rte_mempool_get(ttld.ndata->mp, (void **)&m)) {
        LOG_DBG("rte_mempool_get failed");
        return NULL;
    }

    tasvir_fn_info *fni;
    HASH_FIND(h_fnptr, ttld.ht_fnptr, &fnptr, sizeof(fnptr), fni);
    assert(fni);

    /* FIXME: former case is only at boot time for a non-root daemon */
    m->h.dst_tid = d->owner->active ? d->owner->tid : ttld.ndata->rootcast_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->nodecast_tid;
    m->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
    m->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    m->h.time_us = d->h ? d->h->update_us : ttld.ndata->time_us;
    m->d = d;
    m->fid = fni->fid;
    ptr = &m->data[TASVIR_ALIGN_ARG(fni->ret_len)];

    for (i = 0; i < fni->argc; i++) {
        ptr = &m->data[fni->arg_offsets[i]];
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
                LOG_ERR("missing support for argument of len=%lu", fni->arg_lens[i]);
                abort();
            }
            break;
        }
    }
    m->h.mbuf.pkt_len = m->h.mbuf.data_len =
        TASVIR_ALIGN_ARG((fni->argc > 0 ? fni->arg_lens[i - 1] : 0) + ptr - (uint8_t *)&m->h.eh);

    if (tasvir_service_msg((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0)
        return NULL;

    if (fni->oneway)
        return NULL;

    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    /* garbage collect a previous status */
    if (rs->response)
        rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
    rs->do_free = false;
    rs->id = m->h.id;
    rs->status = TASVIR_RPC_STATUS_PENDING;
    rs->response = NULL;
    rs->cb = NULL;
    return rs;
}

tasvir_rpc_status *tasvir_rpc(tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc(d, fnptr, argp);
    va_end(argp);
    return rs;
}

bool tasvir_rpc_wait(uint64_t timeout_us, void **retval, tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    bool done = false;
    bool failed = false;
    uint64_t end_time_us = tasvir_gettime_us() + timeout_us;
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc(d, fnptr, argp);
    va_end(argp);
    if (!rs)
        return false;

    /* FIXME: horrible error handling */
    while (tasvir_gettime_us() < end_time_us && !done && !failed) {
        switch (rs->status) {
        case TASVIR_RPC_STATUS_INVALID:
        case TASVIR_RPC_STATUS_FAILED:
            failed = true;
            break;
        case TASVIR_RPC_STATUS_PENDING:
            break;
        case TASVIR_RPC_STATUS_DONE:
            if (!rs->response) {
                LOG_DBG("bad response");
                failed = true;
                break;
            }
            /* FIXME: find a better way to ensure state is visible. what if attached to writer view? */
            /* FIXME: useless if rpc is not to update the area */
            done = !rs->response->d ||
                   (rs->response->d->h->active && rs->response->d->h->update_us >= rs->response->h.time_us);
            /* a hack to workaround torn writes during boot time */
            if (unlikely(done && !ttld.thread)) {
                done = !rs->response->d->h->private_tag.external_sync_pending;
            }
            break;
        default:
            LOG_DBG("invalid rpc status %d", rs->status);
            failed = true;
        }
        tasvir_service();
    }

    if (failed || !done) {
        if (rs->response)
            rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
        LOG_INFO("failed (failed=%d done=%d status=%s h=%p update_us=%lu expected_us=%lu)", failed, done,
                 tasvir_rpc_status_type_str[rs->status], rs->response ? (void *)rs->response->d->h : NULL,
                 rs->response ? rs->response->d->h->update_us : 0, rs->response ? rs->response->h.time_us : 0);
        return false;
    }

    if (retval) {
        tasvir_fn_info *fni;
        HASH_FIND(h_fid, ttld.ht_fid, &rs->response->fid, sizeof(rs->response->fid), fni);
        memcpy(retval, rs->response->data, fni->ret_len);
    }
    rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
    return true;
}

int tasvir_rpc_register(tasvir_fn_info *fni) {
    int i;
    ttld.fn_infos[ttld.nr_fns] = *fni;
    fni = &ttld.fn_infos[ttld.nr_fns];
    ptrdiff_t ptr = TASVIR_ALIGN_ARG(fni->ret_len);
    for (i = 0; i < fni->argc; i++) {
        fni->arg_offsets[i] = ptr;
        ptr += TASVIR_ALIGN_ARG(fni->arg_lens[i]);
    }
    HASH_ADD(h_fid, ttld.ht_fid, fid, sizeof(fni->fid), &ttld.fn_infos[ttld.nr_fns]);
    HASH_ADD(h_fnptr, ttld.ht_fnptr, fnptr, sizeof(fni->fnptr), &ttld.fn_infos[ttld.nr_fns]);
    ttld.nr_fns++;
    return 0;
}

static void tasvir_service_msg_rpc_request(tasvir_msg_rpc *m) {
    tasvir_fn_info *fni;
    HASH_FIND(h_fid, ttld.ht_fid, &m->fid, sizeof(m->fid), fni);
    assert(fni);

    /* execute the function */
    fni->fnptr(m->data, fni->arg_offsets);

    if (fni->oneway) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return;
    }

    /* convert the message into a response */
    m->h.dst_tid = m->h.src_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->nodecast_tid;
    m->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
    /* receiver compares time_us with update_us of the area to ensure it includes the updates due to this msg */
    m->h.time_us = ttld.ndata->time_us;

    if (tasvir_service_msg((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0) {
        LOG_DBG("failed to send a response");
    }
}

static void tasvir_service_msg_rpc_response(tasvir_msg_rpc *m) {
    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    rs->status = TASVIR_RPC_STATUS_DONE;
    if (rs->do_free)
        rte_mempool_put(ttld.ndata->mp, (void *)m);
    else
        rs->response = m;
}

static inline void tasvir_service_msg_mem(tasvir_msg_mem *m) {
    /* TODO: log_write and sync */
    if (m->d && m->d->active) {
        // FIXME: assumes no reordering
        tasvir_area_header *h = tasvir_data2shadow(m->d->h);
        h->private_tag.external_sync_pending = !m->last;
    }
    if (m->last && !m->addr)
        return;
    tasvir_log_write(m->addr, m->len);
    tasvir_mov_blocks_stream(tasvir_data2shadow(m->addr), m->line, m->len);
    /* write to both versions because no sync while booting non-root daemon */
    if (unlikely(!ttld.thread || ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX].state == TASVIR_THREAD_STATE_BOOTING)) {
        tasvir_mov_blocks_stream(m->addr, m->line, m->len);
        if (m->d && m->d->active)
            m->d->h->private_tag.external_sync_pending = !m->last;
    }
    rte_mempool_put(ttld.ndata->mp, (void *)m);
}

/* FIXME: not robust */
static inline int tasvir_service_msg(tasvir_msg *m, tasvir_msg_src src) {
    bool is_src_me = src == TASVIR_MSG_SRC_ME;
    bool is_dst_local =
        src == TASVIR_MSG_SRC_NET2US || memcmp(&m->dst_tid.nid, &ttld.ndata->nodecast_tid.nid, sizeof(tasvir_nid)) == 0;
    bool is_dst_me = src == TASVIR_MSG_SRC_NET2ROOT ||
                     (!is_src_me && is_dst_local && (!ttld.thread || m->dst_tid.idx == ttld.thread->tid.idx));

#ifdef TASVIR_DEBUG
    tasvir_print_msg(m, is_src_me, is_dst_me);
#endif
    if (!is_dst_me) { /* no-op when message is ours */
        struct rte_ring *r;
        if (ttld.is_daemon && is_dst_local) {
            r = ttld.ndata->tdata[m->dst_tid.idx == (uint16_t)-1 ? 0 : m->dst_tid.idx].ring_rx;
        } else if (ttld.is_daemon) {
            tasvir_populate_msg_nethdr(m);
            r = ttld.ndata->ring_ext_tx;
        } else
            r = ttld.ndata->tdata[ttld.thread ? ttld.thread->tid.idx : TASVIR_THREAD_DAEMON_IDX].ring_tx;

        if (r && rte_ring_sp_enqueue(r, m) != 0) {
            LOG_DBG("rte_ring_sp_enqueue to ring %p failed", (void *)r);
            rte_mempool_put(ttld.ndata->mp, (void *)m);
            return -1;
        }
        return 0;
    }
    /* end message routing */

    if (m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_service_msg_rpc_request((tasvir_msg_rpc *)m);
    } else if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        tasvir_service_msg_rpc_response((tasvir_msg_rpc *)m);
    } else {
        LOG_DBG("received an unrecognized message type %d", m->type);
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        abort();
        return -1;
    }
    return 0;
}

static inline void tasvir_service_port_tx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int count, i, retval;
    bool tx_fail = false;

    while (!rte_ring_empty(ttld.ndata->ring_ext_tx) && !tx_fail) {
        /* every message on ring_ext_tx must have already populated nethdr */
        count = rte_ring_sc_dequeue_burst(ttld.ndata->ring_ext_tx, (void **)m, TASVIR_PKT_BURST, NULL);

        i = 0;
        do {
            retval = rte_eth_tx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)&m[i], count - i);
            i += retval;
        } while (retval > 0 && i < count);

        if (i < count) {
            tx_fail = true;
            /* FIXME: reorders */
            if (rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)&m[i], count - i, NULL) == 0)
                abort();
            break;
        }
    }
}

static inline void tasvir_service_port_rx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int retval, i;

    while ((retval = rte_eth_rx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)m, TASVIR_PKT_BURST)) > 0) {
        for (i = 0; i < retval; i++) {
            if (m[i]->eh.ether_type == rte_cpu_to_be_16(TASVIR_ETH_PROTO)) {
                ttld.ndata->sync_stats_cur.cumbytes_rx += m[i]->mbuf.pkt_len;
                ttld.ndata->sync_stats_cur.cumpkts_rx++;

                if (is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->mac_addr)) {
                    tasvir_service_msg(m[i], TASVIR_MSG_SRC_NET2US);
                } else if (is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->update_tid.nid.mac_addr)) {
                    tasvir_service_msg_mem((tasvir_msg_mem *)m[i]);
                } else if (ttld.is_root &&
                           is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->rootcast_tid.nid.mac_addr)) {
                    tasvir_service_msg(m[i], TASVIR_MSG_SRC_NET2ROOT);
                } else {
                    rte_mempool_put(ttld.ndata->mp, (void *)m[i]);
                }
            } else {
                rte_mempool_put(ttld.ndata->mp, (void *)m[i]);
            }
        }
    }
}

static inline void tasvir_service_ring(struct rte_ring *ring) {
    tasvir_msg *m[TASVIR_RING_SIZE];
    unsigned int count, i;

    if (rte_ring_empty(ring))
        return;

    while ((count = rte_ring_sc_dequeue_burst(ring, (void **)m, TASVIR_RING_SIZE, NULL)) > 0) {
        for (i = 0; i < count; i++)
            tasvir_service_msg(m[i], TASVIR_MSG_SRC_LOCAL);
    }
}

/* sync */

static inline void tasvir_schedule_sync(tasvir_area_desc *d) {
    if (!d->owner)
        return;

    tasvir_area_header *h_new = tasvir_is_mapped_rw(d) ? d->h : tasvir_data2shadow(d->h);
    if (!h_new->active || h_new->private_tag.external_sync_pending) {
        return;
    }

    if (ttld.ndata->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
        LOG_ERR("more jobs than free slots");
        abort();
    }
    tasvir_sync_job *j = &ttld.ndata->jobs[ttld.ndata->nr_jobs];
    j->d = d;
    j->done = false;
    atomic_init(&j->offset, 0);
    atomic_init(&j->bytes_seen, 0);
    atomic_init(&j->bytes_updated, 0);

    ttld.ndata->job_bytes += d->offset_log_end;
    ttld.ndata->nr_jobs++;
}

/* FIXME: expects len to be aligned */
static inline size_t __attribute__((hot))
tasvir_sync_job_run_helper(uint8_t *src, tasvir_log_t *log_internal, size_t len, bool is_rw) {
    size_t nbits0 = 0;
    size_t nbits1 = 0;
    size_t nbits1_seen = 0;
    size_t nbits_seen = 0;
    size_t nbits_total = len >> TASVIR_SHIFT_BIT;
    uint8_t nbits_same;
    uint8_t nbits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nbits_total);

    tasvir_log_t *log = tasvir_data2log(src);
    tasvir_log_t log_val = *log;

    uint8_t *dst = is_rw ? tasvir_data2shadow(src) : src;
    src = is_rw ? src : tasvir_data2shadow(src);

    while (nbits_total > nbits_seen) {
        nbits_same = _lzcnt_u64(log_val);
        if (nbits_same > 0) {
            nbits_same = MIN(nbits_unit_left, nbits_same);
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
                    tasvir_mov_blocks_stream(dst, src, nbits1 << TASVIR_SHIFT_BIT);
                src += tmp;
                dst += tmp;
                nbits0 = nbits1 = 0;
            }

            nbits_same = _lzcnt_u64(~log_val);
            nbits_same = MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits1 += nbits_same;
            nbits1_seen += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val = (log_val << (nbits_same - 1)) << 1;
        }

        if (nbits_unit_left == 0) {
            nbits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nbits_total - nbits_seen);
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
        tasvir_mov_blocks_stream(dst, src, nbits1 << TASVIR_SHIFT_BIT);
    }

    return nbits1_seen << TASVIR_SHIFT_BIT;
}

/* returns true if the job is done */
static inline bool __attribute__((hot)) tasvir_sync_job_run(tasvir_sync_job *j) {
    if (j->done)
        return true;

    size_t seen = 0;
    size_t updated = 0;
    size_t offset;
    bool is_rw = tasvir_is_mapped_rw(j->d);
    tasvir_area_header *h_new = is_rw ? j->d->h : tasvir_data2shadow(j->d->h);
    tasvir_log_t *log_base = tasvir_is_local(j->d) ? h_new->diff_log[0].data : NULL;
    tasvir_log_t *log;

    while ((offset = atomic_fetch_add(&j->offset, ttld.ndata->job_bytes)) < j->d->offset_log_end) {
        size_t len = MIN(ttld.ndata->job_bytes, j->d->offset_log_end - offset);
        seen += len;
        log = log_base ? log_base + (offset >> TASVIR_SHIFT_UNIT) : NULL;
        updated += tasvir_sync_job_run_helper((uint8_t *)j->d->h + offset, log, len, is_rw);
    }

    if (seen) {
        size_t seen_before = atomic_fetch_add(&j->bytes_seen, seen);
        if (updated)
            updated += atomic_fetch_add(&j->bytes_updated, updated);
        if (seen + seen_before == j->d->offset_log_end) {
            if (tasvir_is_local(j->d) && (updated || atomic_load_explicit(&j->bytes_updated, memory_order_relaxed))) {
                tasvir_area_header *h_old = is_rw ? tasvir_data2shadow(j->d->h) : j->d->h;
                h_old->update_us = h_new->update_us = h_old->diff_log[0].end_us = h_new->diff_log[0].end_us =
                    ttld.ndata->time_us;
                h_old->version = h_old->diff_log[0].version_end = h_new->diff_log[0].version_end = h_new->version++;
                *log_base |= 1UL << 62; /* mark second cacheline modified */
            }
            j->done = true;
        }
    }

    return j->done;
}

static inline void tasvir_service_sync_prepare() {
    size_t nr_threads = 0;
    ttld.ndata->job_bytes = 0;

    /* heartbeat: declare unresponsive threads dead */
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            ttld.ndata->tdata[tid].do_sync = false;

            /* quick check to see if thread is alive */
            /* FIXME: ttld.ndata->time_us - ttld.ndata->tdata[tid].update_us > ttld.node->heartbeat_us */
            if (kill(ttld.node->threads[tid].tid.pid, 0) == -1 && errno == ESRCH) {
                tasvir_kill_thread(&ttld.node->threads[tid]);
                continue;
            }

            /* FIXME: add crash timeout */
            while (ttld.ndata->tdata[tid].in_sync) {
                rte_delay_us_block(1);
            }
            nr_threads++;
        }
    }

    atomic_store(&ttld.ndata->barrier_entry, nr_threads);

    ttld.ndata->nr_jobs = 0;
    tasvir_walk_areas(ttld.root_desc, &tasvir_schedule_sync);

    ttld.ndata->job_bytes /= nr_threads * 8;
    ttld.ndata->job_bytes = 1 << __TASVIR_LOG2(ttld.ndata->job_bytes);
    if (ttld.ndata->job_bytes < 64 * 1024)
        ttld.ndata->job_bytes = 64 * 1024;

    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING)
            ttld.ndata->tdata[tid].do_sync = true;
    }
}

/* TODO: could use AVX */
static inline void tasvir_rotate_logs(tasvir_area_desc *d) {
    if (!d->active)
        return;

    /* always rotate the first one (assumption: rotate called right after an external sync)
     * rotate the second one after five seconds
     * rotate the third one after 15 seconds
     */
    uint64_t delta_us[TASVIR_NR_AREA_LOGS - 1] = {0, 5 * S2US, 15 * S2US};
    for (int i = TASVIR_NR_AREA_LOGS - 2; i >= 0; i--) {
        tasvir_area_log *log = &d->h->diff_log[i];
        tasvir_area_log *log_next = &d->h->diff_log[i + 1];
        tasvir_area_log *log2 = tasvir_data2shadow(log);
        tasvir_area_log *log2_next = tasvir_data2shadow(log_next);

        if (log->version_end > log->version_start && ttld.ndata->time_us - log->start_us > delta_us[i]) {
            tasvir_log_t *ptr = log->data;
            tasvir_log_t *ptr_next = log_next->data;
            tasvir_log_t *ptr_last = log_next->data;
            for (; ptr < ptr_last; ptr++, ptr_next++) {
                if (*ptr) {
                    *ptr_next |= *ptr;
                    *ptr = 0;
                }
            }
            LOG_DBG("%s rotating %d(v%lu-%lu,t%lu-%lu)->%d(v%lu-%lu,t%lu-%lu)", d->name, i, log->version_start,
                    log->version_end, log->start_us, log->end_us, i + 1, log_next->version_start, log_next->version_end,
                    log_next->start_us, log_next->end_us);
            log->version_start = log_next->version_end = log2->version_start = log2_next->version_end =
                log->version_end;
            log->start_us = log_next->end_us = log2->start_us = log2_next->end_us = log->end_us;
        }
    }
}

static inline void tasvir_msg_mem_generate(tasvir_area_desc *d, void *addr, size_t len, bool last, bool is_rw) {
    tasvir_msg_mem *m[TASVIR_PKT_BURST];
    size_t i = 0;

    while (rte_mempool_get_bulk(ttld.ndata->mp, (void **)m, TASVIR_PKT_BURST)) {
        LOG_DBG("rte_mempool_get_bulk failed");
        tasvir_service_port_tx();
    }

    while (len > 0) {
        m[i]->h.dst_tid = ttld.ndata->update_tid;
        m[i]->h.src_tid = ttld.thread->tid;
        m[i]->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
        m[i]->h.type = TASVIR_MSG_TYPE_MEM;
        m[i]->h.time_us = ttld.ndata->time_us;
        m[i]->d = d;
        m[i]->addr = addr;
        m[i]->len = MIN(TASVIR_CACHELINE_BYTES * TASVIR_NR_CACHELINES_PER_MSG, len);
        m[i]->h.mbuf.pkt_len = m[i]->h.mbuf.data_len =
            m[i]->len + offsetof(tasvir_msg_mem, line) - offsetof(tasvir_msg, eh);
        tasvir_mov_blocks_stream(m[i]->line, is_rw ? tasvir_data2shadow(addr) : addr, m[i]->len);

        addr = (uint8_t *)addr + m[i]->len;
        len -= m[i]->len;
        m[i]->last = len == 0 ? last : false;
        tasvir_populate_msg_nethdr((tasvir_msg *)m[i]);

        if (++i >= TASVIR_PKT_BURST) {
            while (rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)m, i, NULL) != i)
                tasvir_service_port_tx();

            while (rte_mempool_get_bulk(ttld.ndata->mp, (void **)m, TASVIR_PKT_BURST)) {
                LOG_DBG("rte_mempool_get_bulk failed");
                tasvir_service_port_tx();
            }
            i = 0;
        }
    }

    while (i > 0 && rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)m, i, NULL) != i)
        tasvir_service_port_tx();
    rte_mempool_put_bulk(ttld.ndata->mp, (void **)&m[i], TASVIR_PKT_BURST - i);
}

static inline size_t tasvir_sync_area_external_boot(tasvir_area_desc *d, bool boot) {
    if (!d || !d->owner)
        return 0;

    if (d->sync_int_us < ttld.ndata->sync_int_us) {
        ttld.ndata->sync_int_us = d->sync_int_us;
        LOG_INFO("updating internal sync interval to %luus", ttld.ndata->sync_int_us);
    }
    if (d->sync_ext_us < ttld.ndata->sync_ext_us) {
        ttld.ndata->sync_ext_us = d->sync_ext_us;
        LOG_INFO("updating external sync interval to %luus", ttld.ndata->sync_ext_us);
    }

    if (!tasvir_is_local(d) || d->h->diff_log[0].version_end == 0)
        return 0;

    int i;
    if (!d->pd && ttld.is_root) {
        tasvir_msg_mem_generate(NULL, d, TASVIR_ALIGNX(sizeof(tasvir_area_desc), TASVIR_CACHELINE_BYTES), true, true);
    }

    size_t nbits0 = 0;
    size_t nbits1 = 0;
    size_t nbits1_seen = 0;
    size_t nbits_seen = 0;
    size_t nbits_total = d->offset_log_end >> TASVIR_SHIFT_BIT;
    uint8_t nbits_same;
    uint8_t nbits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nbits_total);

    uint8_t *src = (uint8_t *)d->h;
    int pivot = 0;
    tasvir_log_t *log[TASVIR_NR_AREA_LOGS];
    tasvir_log_t log_val = 0;

    for (pivot = 0; pivot < TASVIR_NR_AREA_LOGS; pivot++) {
        if (!boot && ttld.ndata->last_sync_ext_end > d->h->diff_log[pivot].end_us) {
            break;
        }
        log[pivot] = d->h->diff_log[pivot].data;
        log_val |= *log[pivot];
    }

    if (pivot == 0)
        return 0;

    bool is_rw = tasvir_is_mapped_rw(d);
    while (nbits_total > nbits_seen) {
        nbits_same = _lzcnt_u64(log_val);
        if (nbits_same > 0) {
            nbits_same = MIN(nbits_unit_left, nbits_same);
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
                    tasvir_msg_mem_generate(d, src, nbits1 << TASVIR_SHIFT_BIT, false, is_rw);
                src += tmp;
                nbits0 = nbits1 = 0;
            }

            nbits_same = _lzcnt_u64(~log_val);
            nbits_same = MIN(nbits_unit_left, nbits_same);
            nbits_seen += nbits_same;
            nbits1 += nbits_same;
            nbits1_seen += nbits_same;
            nbits_unit_left -= nbits_same;
            log_val = (log_val << (nbits_same - 1)) << 1;
        }

        if (nbits_unit_left == 0) {
            nbits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nbits_total - nbits_seen);
            log_val = 0;
            for (i = 0; i < pivot; i++) {
                log[i]++;
                log_val |= *log[i];
            }
        }
    }

    if (nbits1 > 0) {
        tasvir_msg_mem_generate(d, src, nbits1 << TASVIR_SHIFT_BIT, true, is_rw);
        tasvir_rotate_logs(d);
    } else if (nbits1_seen > 0) {
        tasvir_msg_mem_generate(d, NULL, 0, true, is_rw);
    }

    return nbits1_seen << TASVIR_SHIFT_BIT;
}

static inline size_t tasvir_sync_area_external(tasvir_area_desc *d) { return tasvir_sync_area_external_boot(d, false); }

static inline void tasvir_sync_external() {
    ttld.ndata->last_sync_ext_start = ttld.ndata->time_us;
    tasvir_walk_areas(ttld.root_desc, &tasvir_sync_area_external);
    ttld.ndata->time_us = tasvir_gettime_us();
    ttld.ndata->last_sync_ext_end = ttld.ndata->time_us;
}

static inline int tasvir_service_sync() {
    ttld.tdata->in_sync = true;
    ttld.tdata->do_sync = false;
    if (ttld.is_daemon) {
        ttld.ndata->last_sync_start = ttld.tdata->update_us;
    }

    size_t cur_job;
    uint64_t time_us = ttld.ndata->time_us;

    _mm_sfence();

    if (!tasvir_barrier_wait(&ttld.ndata->barrier_entry, TASVIR_BARRIER_ENTER_US)) {
        ttld.tdata->in_sync = false;
        if (ttld.is_daemon)
            ttld.ndata->sync_stats_cur.failed++;
        return -1;
    }

    /* special case for syncing root desc because it is an orphan */
    if (ttld.is_daemon) {
        /* FIXME: what if root is external? check address mapping when d owner is external */
        /* FIXME: no internal log to capture root desc changes? */
        tasvir_sync_job_run_helper((uint8_t *)ttld.root_desc, NULL, TASVIR_ALIGN(sizeof(tasvir_area_desc)),
                                   tasvir_is_mapped_rw(ttld.root_desc));
        ttld.ndata->sync_req = false;
    }

    bool done;
    do {
        done = true;
        for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
            /* reduce contention a bit */
            size_t idx = (cur_job + ttld.thread->tid.idx) % ttld.ndata->nr_jobs;
            done &= tasvir_sync_job_run(&ttld.ndata->jobs[idx]);
        }
    } while (!done);

    _mm_sfence();

    ttld.tdata->update_us = tasvir_gettime_us();

    if (ttld.is_daemon) {
        for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
            ttld.ndata->sync_stats_cur.cumbytes += ttld.ndata->jobs[cur_job].bytes_updated;
        }
        ttld.ndata->time_us = ttld.tdata->update_us;
        ttld.ndata->last_sync_end = ttld.tdata->update_us;
        ttld.ndata->sync_stats_cur.count++;
        ttld.ndata->sync_stats_cur.cumtime_us += ttld.tdata->update_us - time_us;
    }

    ttld.tdata->in_sync = false;
    return 0;
}

tasvir_sync_stats tasvir_sync_stats_get() { return ttld.ndata->sync_stats; }

void tasvir_sync_stats_reset() {
    memset(&ttld.ndata->sync_stats, 0, sizeof(tasvir_sync_stats));
    memset(&ttld.ndata->sync_stats_cur, 0, sizeof(tasvir_sync_stats));
}

static inline void tasvir_service_stats() {
    uint64_t MS = 1 * 1000;  // in us
    uint64_t S = MS * 1000;  // in us
    uint64_t interval_us = ttld.ndata->time_us - ttld.ndata->last_stat;
    ttld.ndata->last_stat = ttld.ndata->time_us;
    tasvir_sync_stats *cur = &ttld.ndata->sync_stats_cur;
    tasvir_sync_stats *avg = &ttld.ndata->sync_stats;

    struct rte_eth_stats s;
    rte_eth_stats_get(0, &s);

    LOG_INFO(
        "sync=%lu/s,%lu/s sync_t=%.1f%%,%luus/sync change=%luKB/s,%luKB/sync "
        "\n                                      "
        "rx=%luKB/s,%luKpps tx=%luKB/s,%luKpps "
        "(ipkts=%lu ibytes=%lu ierr=%lu imiss=%lu inombuf=%lu"
        ",opkts=%lu obytes=%lu oerr=%lu)",
        S * cur->count / interval_us, S * cur->failed / interval_us, 100. * cur->cumtime_us / interval_us,
        cur->count > 0 ? cur->cumtime_us / cur->count : 0, MS * cur->cumbytes / interval_us,
        cur->count > 0 ? cur->cumbytes / 1000 / cur->count : 0, MS * cur->cumbytes_rx / interval_us,
        MS * cur->cumpkts_rx / interval_us, MS * cur->cumbytes_tx / interval_us, MS * cur->cumpkts_tx / interval_us,
        s.ipackets, s.ibytes, s.ierrors, s.imissed, s.rx_nombuf, s.opackets, s.obytes, s.oerrors);

    avg->count += cur->count;
    avg->failed += cur->failed;
    avg->cumtime_us += cur->cumtime_us;
    avg->cumbytes += cur->cumbytes;
    avg->cumbytes_rx += cur->cumbytes_rx;
    avg->cumpkts_rx += cur->cumpkts_rx;
    avg->cumbytes_tx += cur->cumbytes_rx;
    avg->cumpkts_tx += cur->cumpkts_rx;

    cur->count = 0;
    cur->failed = 0;
    cur->cumtime_us = 0;
    cur->cumbytes = 0;
    cur->cumbytes_rx = 0;
    cur->cumpkts_rx = 0;
    cur->cumbytes_tx = 0;
    cur->cumpkts_tx = 0;
    // tasvir_walk_areas(ttld.root_desc, &tasvir_print_area);
}

static inline void tasvir_service_daemon() {
    /* update time */
    uint64_t now = tasvir_gettime_us();
    /* experimental: set granularity of global timer to 5us
     * reduces cross-core traffic for reading this global time
     * (i.e., cache line spends more time in the shared state)
     */
    if (now - ttld.ndata->time_us > 5) {
        ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX].update_us = ttld.ndata->time_us = now;
    }

    /* service rings */
    if (ttld.node) {
        for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++)
            if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING ||
                ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_BOOTING) {
                tasvir_service_ring(ttld.ndata->tdata[tid].ring_tx);
            }
    }

    /* service physical port */
    tasvir_service_port_rx();
    tasvir_service_port_tx();

    if (likely(ttld.tdata->state == TASVIR_THREAD_STATE_RUNNING)) {
        if (ttld.ndata->time_us - ttld.ndata->last_sync_ext_end >= ttld.ndata->sync_ext_us) {
            tasvir_sync_external();
        }

        if (ttld.ndata->sync_req || ttld.ndata->time_us - ttld.ndata->last_sync_end >= ttld.ndata->sync_int_us) {
            tasvir_service_sync_prepare();
        }

        if (unlikely(ttld.ndata->time_us - ttld.ndata->last_stat >= TASVIR_STAT_US)) {
            tasvir_service_stats();
        }
    }
}

bool tasvir_service() {
    if (ttld.is_daemon) {
        tasvir_service_daemon();
    } else if (ttld.thread) {
        // assuming rdtsc is well sync'ed across cores
        tasvir_service_ring(ttld.ndata->tdata[ttld.thread->tid.idx].ring_rx);
        ttld.ndata->tdata[ttld.thread->tid.idx].update_us = ttld.ndata->time_us;
    } else
        tasvir_service_ring(ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX].ring_rx);

    if (ttld.thread && ttld.tdata->do_sync) {
        return tasvir_service_sync() == 0;
    }

    return false;
}

bool tasvir_service_wait(uint64_t timeout_us) {
    bool retval = false;
    uint64_t end_time_us = ttld.ndata->tdata[ttld.thread->tid.idx].update_us + timeout_us;
    while (ttld.ndata->tdata[ttld.thread->tid.idx].update_us < end_time_us && !(retval = tasvir_service())) {
        rte_delay_us_block(1);
        ttld.ndata->sync_req = true;
    }
    return retval;
}
