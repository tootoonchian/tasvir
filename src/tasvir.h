/**
 * @file
 *   tasvir.h
 * @brief
 *   Function prototypes for Tasvir.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_SRC_TASVIR_H_
#define TASVIR_SRC_TASVIR_H_
#pragma once

#include <assert.h>
#include <errno.h>
#include <immintrin.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <tasvir/tasvir.h>
#include <time.h>
#include <x86intrin.h>

/**
 *
 */
typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_MEM,
    TASVIR_MSG_TYPE_RPC_ONEWAY,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

/**
 *
 */
typedef struct __attribute__((__packed__)) tasvir_msg {
    struct {
        struct rte_mbuf mbuf;
        uint8_t pad_[RTE_PKTMBUF_HEADROOM];
    };
    struct ether_hdr eh;
    struct ip iph;
    tasvir_tid src_tid;
    tasvir_tid dst_tid;
    tasvir_msg_type type;
    uint16_t id;
    uint64_t time_us;
} tasvir_msg;

/**
 *
 */
typedef struct __attribute__((__packed__)) tasvir_msg_rpc {
    tasvir_msg h;
    tasvir_area_desc *d;
    uint32_t fid;
    uint8_t data[1] __attribute__((aligned(sizeof(tasvir_arg_promo_t)))); /* for compatibility */
} tasvir_msg_rpc;

/**
 *
 */
typedef struct __attribute__((__packed__)) tasvir_msg_mem {
    tasvir_msg h;
    tasvir_area_desc *d;
    void *addr;
    size_t len;
    bool last;
    tasvir_cacheline line[TASVIR_NR_CACHELINES_PER_MSG] __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
} tasvir_msg_mem;

TASVIR_STATIC_ASSERT(sizeof(tasvir_msg_mem) - sizeof(struct rte_mbuf) - RTE_PKTMBUF_HEADROOM < 1518,
                     "tasvir_msg_mem exceeds ethernet MTU.");

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

// static const char *tasvir_thread_state_str[] = {"invalid", "dead", "booting", "running"};

typedef enum {
    TASVIR_MSG_SRC_INVALID = 0,
    TASVIR_MSG_SRC_ME = 1,
    TASVIR_MSG_SRC_LOCAL = 2,
    TASVIR_MSG_SRC_NET2US = 3,
    TASVIR_MSG_SRC_NET2ROOT = 4,
} tasvir_msg_src;

// static const char *tasvir_msg_src_str[] = {"invalid", "me", "local", "net2us", "net2root"};

struct tasvir_local_tdata { /* thread data */
    uint64_t update_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    tasvir_thread_state state;
    int sync_seq;
    struct {
        bool do_sync; /* only updated by daemon */
        bool in_sync; /* only updated by thread */
    };
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

    uint64_t barrier_end_tsc;
    atomic_int barrier_entry;
    atomic_int barrier_seq;
    pthread_mutex_t mutex_init;
    struct rte_ring *ring_ext_tx;

    /* daemon data */
    struct ether_addr mac_addr;
    uint16_t port_id;

    tasvir_tid update_tid;
    tasvir_tid rootcast_tid;
    tasvir_tid nodecast_tid;

    /* sync times and stats */
    uint64_t last_stat;
    uint64_t last_sync_int_start;
    uint64_t last_sync_int_end;
    uint64_t last_sync_ext_start;
    uint64_t last_sync_ext_end;
    tasvir_stats stats_cur;
    tasvir_stats stats;

    size_t nr_jobs;
    tasvir_sync_job jobs[TASVIR_NR_SYNC_JOBS];

    bool sync_req;
    bool stat_reset_req;
    bool stat_update_req;

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

    uint16_t nr_msgs;
    int fd;
    int nr_fns;
    tasvir_fn_desc fn_descs[TASVIR_NR_FN];
    tasvir_fn_desc *ht_fid;
    tasvir_fn_desc *ht_fnptr;
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
        fprintf(stderr, GRN "%16.3f " CYN "%-22.22s " MSG_CLR FMT "\n" RESET,           \
                ttld.ndata ? ttld.ndata->time_us / 1000. : 0, __func__, ##__VA_ARGS__); \
    }

#ifdef __AVX512F__
#define TASVIR_VEC_UNIT 64
#elif __AVX2__
#define TASVIR_VEC_UNIT 32
#elif __AVX__
#define TASVIR_VEC_UNIT 16
#else
#error Tasvir requires AVX, AVX2, or AVX512 support
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

int tasvir_attach_helper(tasvir_area_desc *, tasvir_node *);
tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core);
int tasvir_init_dpdk(uint16_t core);
#ifdef TASVIR_DAEMON
int tasvir_init_port();
void tasvir_stats_update();
#endif
void tasvir_init_rpc();
int tasvir_init_finish(tasvir_thread *);
void tasvir_sched_sync_internal();
int tasvir_service_msg(tasvir_msg *, tasvir_msg_src);
void tasvir_service_port_tx();
int tasvir_service_sync();
int tasvir_sync_internal();
int tasvir_sync_external();
size_t tasvir_sync_external_area(tasvir_area_desc *d, bool init);

/* utils */

/* FIXME: consistency checks... */
static inline bool tasvir_area_is_valid(const tasvir_area_desc *d) { return d && d->active && d->h && d->owner; }
static inline bool tasvir_area_is_local(const tasvir_area_desc *d) { return d->h->private_tag.local; }
static inline bool tasvir_area_is_mapped_rw(const tasvir_area_desc *d) { return d->h->private_tag.rw; }

static inline uint64_t tasvir_gettime_us() { return ttld.ndata->tsc2usec_mult * tasvir_rdtsc(); }
// static inline uint64_t tasvir_tsc2usec(uint64_t tsc) { return tsc * ttld.ndata->tsc2usec_mult; }
static inline uint64_t tasvir_usec2tsc(uint64_t us) { return us / ttld.ndata->tsc2usec_mult; }

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

static inline void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c[i]);
    }
    if (d->owner == t)
        tasvir_update_owner(d, ttld.thread);
}

/* caller contract: is_daemon and tasvir_is_thread_local(t) */
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

static inline void tasvir_tid2str(tasvir_tid tid, size_t buf_size, char *buf) {
    ether_format_addr(buf, buf_size, &tid.nid.mac_addr);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), ":%d", tid.idx);
}

/* assumption src and dst are TASVIR_VEC_UNIT aligned, len > 0 and multiple of TASVIR_VEC_UNIT */
static inline void tasvir_mov_blocks(void *dst, const void *src, size_t len) {
    do {
#if TASVIR_VEC_UNIT == 64
        __m512i m = _mm512_load_si512((const __m512i *)src);
        _mm512_store_si512((__m512i *)dst, m);
#elif TASVIR_VEC_UNIT == 32
        __m256i m = _mm256_load_si256((const __m256i *)src);
        _mm256_store_si256((__m256i *)dst, m);
#elif TASVIR_VEC_UNIT == 16
        __m128i m = _mm_load_si128((__m128i *)src);
        _mm_store_si128((__m128i *)dst, m);
#else
#error unsupported TASVIR_VEC_UNIT
#endif
        dst = (uint8_t *)dst + TASVIR_VEC_UNIT;
        src = (uint8_t *)src + TASVIR_VEC_UNIT;
    } while ((len -= TASVIR_VEC_UNIT) > 0);
}

/* assumption src and dst are TASVIR_VEC_UNIT aligned, len > 0 and multiple of TASVIR_VEC_UNIT */
static inline void tasvir_mov_blocks_stream(void *dst, const void *src, size_t len) {
    do {
#if TASVIR_VEC_UNIT == 64
        __m512i m = _mm512_stream_load_si512((__m512i *)src);
        _mm512_stream_si512((__m512i *)dst, m);
#elif TASVIR_VEC_UNIT == 32
        __m256i m = _mm256_stream_load_si256((__m256i *)src);
        _mm256_stream_si256((__m256i *)dst, m);
#elif TASVIR_VEC_UNIT == 16
        __m128i m = _mm_stream_load_si128((__m128i *)src);
        _mm_stream_si128((__m128i *)dst, m);
#else
#error unsupported TASVIR_VEC_UNIT
#endif
        dst = (uint8_t *)dst + TASVIR_VEC_UNIT;
        src = (uint8_t *)src + TASVIR_VEC_UNIT;
    } while ((len -= TASVIR_VEC_UNIT) > 0);
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
    ttld.ndata->stats_cur.total_bytes_tx += m->mbuf.pkt_len;
    ttld.ndata->stats_cur.total_pkts_tx++;
}

__attribute__((unused)) static inline void tasvir_print_area(tasvir_area_desc *d) {
    LOG_DBG("name=%s owner=%p version=%lu update_us=%lu", d->name, (void *)d->owner, d->h ? d->h->version : 0,
            d->h ? d->h->update_us : 0);
}

static inline void tasvir_print_msg(tasvir_msg *m, bool is_src_me, bool is_dst_me) {
    static const char *tasvir_msg_type_str[] = {"invalid", "memory", "rpc_oneway", "rpc_request", "rpc_reply"};

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
        /* FIXME: badly insecure */
        tasvir_fn_desc *fnd = &ttld.fn_descs[mr->fid];

        LOG_DBG("%c %s->%s id=%d type=%s desc=%s f=%s", direction, src_str, dst_str, m->id,
                tasvir_msg_type_str[m->type], mr->d ? mr->d->name : "root", fnd->name);
    } else {
        LOG_DBG("%c %s->%s id=%d type=%s", direction, src_str, dst_str, m->id, tasvir_msg_type_str[m->type]);
    }
    // tasvir_hexdump(&m->h.eh, m->h.mbuf.data_len);
}

typedef size_t (*tasvir_fnptr_walkcb)(tasvir_area_desc *);
static inline size_t tasvir_walk_areas(tasvir_area_desc *d, tasvir_fnptr_walkcb fnptr) {
    if (!d->active)
        return 0;
    size_t retval = 0;
    retval += fnptr(d);
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++) {
            retval += tasvir_walk_areas(&c[i], fnptr);
        }
    }
    return retval;
}
#endif /* TASVIR_SRC_TASVIR_TASVIR_H_ */
