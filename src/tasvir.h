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
#include <time.h>
#include <x86intrin.h>

#include <tasvir/tasvir.h>

typedef enum {
    TASVIR_THREAD_STATE_INVALID = 0,
    TASVIR_THREAD_STATE_DEAD,
    TASVIR_THREAD_STATE_BOOTING,
    TASVIR_THREAD_STATE_RUNNING,
    TASVIR_THREAD_STATE_SLEEPING
} tasvir_thread_state;

// static const char *tasvir_thread_state_str[] = {"invalid", "dead", "booting", "running"};

typedef struct tasvir_nid {
    struct ether_addr mac_addr; /* node identified by its mac address */
} tasvir_nid;

typedef struct tasvir_tid {
    tasvir_nid nid; /* node id */
    uint16_t idx;   /* local index */
    uint16_t core;  /* local core */
    pid_t pid;      /* pid */
} tasvir_tid;

struct tasvir_thread { /* thread context */
    uint64_t time_us;
    tasvir_tid tid;
    tasvir_thread_state state; /* thread state. updated by daemon only */
};

struct tasvir_node { /* node context */
    tasvir_nid nid;
    uint32_t heartbeat_us;
    tasvir_thread threads[TASVIR_NR_THREADS_LOCAL];
};

typedef enum {
    TASVIR_AREA_CACHE_ACTIVE = 1 << 0,    /* set once area is bootstrapped */
    TASVIR_AREA_CACHE_MAPPED_RW = 1 << 1, /* distinguish reader and writer copies */
    TASVIR_AREA_CACHE_LOCAL = 1 << 2,     /* area owner is local */
    TASVIR_AREA_CACHE_NETUPDATE = 1 << 3, /* network updates are being applied */
    TASVIR_AREA_CACHE_SLEEPING = 1 << 4,  /* not syncing temporarily */
} tasvir_area_cache_flag;

typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_MEM,
    TASVIR_MSG_TYPE_RPC_ONEWAY,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

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
    uint64_t version; /* version at source */
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
    TASVIR_MSG_SRC_INVALID = 0,
    TASVIR_MSG_SRC_ME = 1,
    TASVIR_MSG_SRC_LOCAL = 2,
    TASVIR_MSG_SRC_NET2US = 3,
    TASVIR_MSG_SRC_NET2ROOT = 4,
} tasvir_msg_src;

// static const char *tasvir_msg_src_str[] = {"invalid", "me", "local", "net2us", "net2root"};

struct __attribute__((aligned(8))) tasvir_local_tdata { /* thread data */
    uint64_t time_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    tasvir_thread_state state;     /* thread state. updated by daemon only */
    tasvir_thread_state state_req; /* state transition request by thread */
    size_t prev_sync_seq;          /* prev sync sequence number. updated by thread only. */
    size_t next_sync_seq;          /* next sync sequence number. updated by daemon only. */
};

struct tasvir_sync_job {
    tasvir_area_desc *d;
    bool done;
    bool admit;
    atomic_size_t offset __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
    atomic_size_t bytes_seen;
    atomic_size_t bytes_updated;
};

struct __attribute__((aligned(8))) tasvir_local_ndata { /* node data */
    uint64_t boot_us;
    uint64_t time_us;
    uint64_t sync_int_us;
    uint64_t sync_ext_us;
    uint64_t job_bytes;
    double tsc2usec_mult;
    struct rte_mempool *mp;

    uint64_t barrier_end_tsc;
    atomic_size_t barrier_cnt;
    atomic_size_t barrier_seq;
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
};

/* thread-internal data */
struct __attribute__((aligned(4096))) tasvir_tls_data {
    tasvir_area_desc *root_desc; /* root area descriptor */
    tasvir_area_desc *node_desc; /* current node's area descriptor */
    tasvir_node *node;           /* current node's global data */
    tasvir_thread *thread;       /* current thread's global data */
    tasvir_local_ndata *ndata;   /* current node's node-local data */
    tasvir_local_tdata *tdata;   /* current thread's node-local data */

    uint16_t nr_msgs;
    int fd;
    int nr_fns;
    tasvir_fn_desc fn_descs[TASVIR_NR_FN];
    tasvir_fn_desc *ht_fid;
    tasvir_fn_desc *ht_fnptr;
    tasvir_rpc_status status_l[TASVIR_NR_RPC_MSG];

    bool is_root;
} ttld; /* tasvir thread-local data */


_Static_assert(sizeof(tasvir_local_ndata) <= TASVIR_SIZE_LOCAL,
               "TASVIR_SIZE_LOCAL smaller than sizeof(tasvir_local_ndata)");

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

/* area utils */

static inline bool tasvir_area_is_attached(const tasvir_area_desc *d, const tasvir_node *node) {
    if (d->h && d->h->d == d) {
        if (!node)
            return true;
        for (size_t i = 0; i < d->h->nr_users; i++)
            if (d->h->users[i].node == node)
                return true;
    }
    return false;
}

static inline bool tasvir_area_is_active(const tasvir_area_desc *d) {
    return d && d->owner && d->h && (d->h->flags_ & TASVIR_AREA_CACHE_ACTIVE);
}

static inline bool tasvir_area_is_active_any(const tasvir_area_desc *d) {
    return d && d->owner && d->h &&
           ((d->h->flags_ & TASVIR_AREA_CACHE_ACTIVE) ||
            (((tasvir_area_header *)tasvir_data2shadow(d->h))->flags_ & TASVIR_AREA_CACHE_ACTIVE));
}

static inline bool tasvir_area_is_local(const tasvir_area_desc *d) {
    return tasvir_area_is_active_any(d) &&
           ((d->h->flags_ & TASVIR_AREA_CACHE_LOCAL) ||
            (((tasvir_area_header *)tasvir_data2shadow(d->h))->flags_ & TASVIR_AREA_CACHE_LOCAL));
}

static inline bool tasvir_area_is_local_by_tid(const tasvir_area_desc *d) {
    return memcmp(&d->owner->tid.nid, &ttld.node->nid, sizeof(tasvir_nid)) == 0;
}

static inline bool tasvir_area_is_mapped_rw(const tasvir_area_desc *d) {
    return tasvir_area_is_active(d) && (d->h->flags_ & TASVIR_AREA_CACHE_MAPPED_RW);
}

typedef size_t (*tasvir_fnptr_walkcb)(tasvir_area_desc *);
static inline size_t tasvir_area_walk(tasvir_area_desc *d, tasvir_fnptr_walkcb fnptr) {
    if (!tasvir_area_is_active_any(d))
        return 0;
    size_t retval = 0;
    retval += fnptr(d);
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++) {
            retval += tasvir_area_walk(&c[i], fnptr);
        }
    }
    return retval;
}

/* i/o utils */

static inline void tasvir_populate_msg_nethdr(tasvir_msg *m) {
    m->mbuf.refcnt = 1;
    m->mbuf.nb_segs = 1;
    ether_addr_copy(&m->dst_tid.nid.mac_addr, &m->eh.d_addr);
    ether_addr_copy(&ttld.ndata->mac_addr, &m->eh.s_addr);
    m->eh.ether_type = rte_cpu_to_be_16(TASVIR_ETH_PROTO);

    // FIXME: not all will be sent out
    ttld.ndata->stats_cur.tx_bytes += m->mbuf.pkt_len;
    ttld.ndata->stats_cur.tx_pkts++;
}

#include "utils.h"

#endif /* TASVIR_SRC_TASVIR_TASVIR_H_ */
