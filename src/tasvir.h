#ifndef TASVIR_SRC_TASVIR_H_
#define TASVIR_SRC_TASVIR_H_
#pragma once

#include <assert.h>
#include <errno.h>
#include <immintrin.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <rte_cycles.h>
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

#define TASVIR_SYNC_LIST_LEN 512

typedef enum {
    TASVIR_THREAD_STATE_INVALID = 0,
    TASVIR_THREAD_STATE_DEAD,
    TASVIR_THREAD_STATE_PREBOOT,
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
    size_t nr_areas;
    tasvir_area_desc *areas_d[TASVIR_NR_AREAS];
    uint64_t areas_v[TASVIR_NR_AREAS];
};

typedef enum {
    TASVIR_AREA_FLAG_ACTIVE = 1 << 0,      /* set once area is bootstrapped */
    TASVIR_AREA_FLAG_MAPPED_RW = 1 << 1,   /* distinguish reader and writer copies */
    TASVIR_AREA_FLAG_LOCAL = 1 << 2,       /* area owner is local */
    TASVIR_AREA_FLAG_SLEEPING = 1 << 3,    /* not syncing temporarily */
    TASVIR_AREA_FLAG_EXT_PENDING = 1 << 4, /* incoming external sync ongoing */
    TASVIR_AREA_FLAG_EXT_IGNORE = 1 << 5,  /* incoming external sync to be ignored */
    TASVIR_AREA_FLAG_EXT_ENQUEUE = 1 << 6, /* incoming external sync to be queued */
} tasvir_area_cache_flag;

typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_MEM,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

typedef struct tasvir_msg tasvir_msg;
typedef struct tasvir_msg_rpc tasvir_msg_rpc;
typedef struct tasvir_msg_mem tasvir_msg_mem;

struct __attribute__((__packed__)) tasvir_msg {
    struct {
        struct rte_mbuf mbuf;
        uint8_t pad_[RTE_PKTMBUF_HEADROOM];
    };
    struct ether_header eh;
    struct ip iph;

    tasvir_msg_type type;
    uint16_t id;

    tasvir_tid src_tid;
    tasvir_tid dst_tid;

    const tasvir_area_desc *d;
    uint64_t version; /* version at source */
};

struct __attribute__((__packed__)) tasvir_msg_rpc {
    tasvir_msg h;
    uint32_t fid;
    uint8_t pad_[4];
    uint8_t data[1];  // __attribute__((aligned(sizeof(tasvir_arg_promo_t)))); /* for compatibility */
};

TASVIR_STATIC_ASSERT(offsetof(tasvir_msg_rpc, data) % sizeof(tasvir_arg_promo_t) == 0,
                     "tasvir_msg_rpc.data is not aligned to sizeof(tasvir_arg_promo_t)");

struct __attribute__((__packed__)) tasvir_msg_mem {
    tasvir_msg h;
    void *addr;
    size_t len;
    uint8_t last;
    uint64_t prev_bytes;
    uint8_t pad_[23];
    tasvir_cacheline line[TASVIR_NR_CACHELINES_PER_MSG];  // __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
};

TASVIR_STATIC_ASSERT(offsetof(tasvir_msg_mem, line[TASVIR_NR_CACHELINES_PER_MSG]) - offsetof(tasvir_msg_mem, h.eh) <
                         1518,
                     "tasvir_msg_mem exceeds ethernet MTU.");
TASVIR_STATIC_ASSERT(offsetof(tasvir_msg_mem, line) % TASVIR_CACHELINE_BYTES == 0,
                     "tasvir_msg_mem.line is not cacheline-aligned");

typedef struct tasvir_local_tdata tasvir_local_tdata;
typedef struct tasvir_local_ndata tasvir_local_ndata;
typedef struct tasvir_sync_job tasvir_sync_job;
typedef struct tasvir_tls_data tasvir_tls_data;

typedef enum {
    TASVIR_MSG_SRC_INVALID = 0,
    TASVIR_MSG_SRC_ME = 1,
    TASVIR_MSG_SRC_LOCAL = 2,
    TASVIR_MSG_SRC_NET = 3,
} tasvir_msg_src;

// static const char *tasvir_msg_src_str[] = {"invalid", "me", "local", "net2us", "net2root"};

/* set prior to sync by daemon and concurrently updated by all during sync */
struct __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_sync_job {
    tasvir_area_desc *d;
    bool self_sync;
    bool done_stage1;  // walking the log
    bool done_stage2;  // updating the header
    bool done_stage3;  // postprocessing
    atomic_size_t offset __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
    atomic_size_t bytes_seen;
    atomic_size_t bytes_updated;
};

typedef struct tasvir_sync_item {
    uint64_t offset_scaled;
    uint32_t len_scaled;
} tasvir_sync_item;

typedef struct __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_sync_list {
    int changed;
    int cnt;
    tasvir_sync_item l[TASVIR_SYNC_LIST_LEN];
} tasvir_sync_list;

struct __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_local_tdata { /* thread data */
    uint64_t time_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    tasvir_thread_state state;     /* thread state. updated by daemon only */
    tasvir_thread_state state_req; /* state transition request by thread */
    size_t prev_sync_seq;          /* prev sync sequence number. updated by thread only. */
    size_t next_sync_seq;          /* next sync sequence number. updated by daemon only. */
    tasvir_sync_list sync_list;
};

struct __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_local_ndata { /* node data */
    uint64_t boot_us;
    uint64_t time_us;
    uint64_t sync_int_us;
    uint64_t sync_ext_us;
    double tsc2usec_mult;
    struct rte_mempool *mp;

    uint64_t barrier_end_tsc;
    atomic_size_t barrier_cnt;
    atomic_size_t barrier_seq;
    pthread_mutex_t mutex_init;
    struct rte_ring *ring_ext_tx;
    struct rte_ring *ring_mem_pending;

    /* daemon data */
    struct ether_addr mac_addr;
    uint16_t port_id;

    /* special tids */
    tasvir_tid boot_tid;     // src tid before thread is initialized
    tasvir_tid memcast_tid;  // dst tid for multicasting memory updates
    tasvir_tid rpccast_tid;  // dst tid for multicasting rpc requests with unknown tid

    /* sync times and stats */
    uint64_t last_stat;
    uint64_t last_sync_int_start;
    uint64_t last_sync_int_end;
    uint64_t last_sync_ext_start;
    uint64_t last_sync_ext_end;
    tasvir_stats stats_cur;
    tasvir_stats stats;

    /* sync jobs */
    size_t job_bytes;
    size_t nr_jobs;
    tasvir_sync_job jobs[TASVIR_NR_SYNC_JOBS];

    /* thread to daemon requests */
    bool node_init_req;
    bool sync_req;
    bool stat_reset_req;
    bool stat_update_req;

    /* thread data */
    tasvir_local_tdata tdata[TASVIR_NR_THREADS_LOCAL];
};

/* thread-internal data */
struct __attribute__((aligned(4096))) tasvir_tls_data {
    double tsc2usec_mult;
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

tasvir_area_desc *tasvir_new_alloc_desc(tasvir_area_desc);
int tasvir_area_add_user(tasvir_area_desc *, tasvir_node *, int);
int tasvir_area_add_user_wait(uint64_t, tasvir_area_desc *, tasvir_node *, int);
tasvir_thread *tasvir_init_thread(pid_t);
int tasvir_init_dpdk();
void tasvir_init_rpc();
int tasvir_init_finish(tasvir_thread *);
void tasvir_sched_sync_internal();
int tasvir_handle_msg_rpc(tasvir_msg *, tasvir_msg_src);
void tasvir_handle_msg_rpc_request(tasvir_msg_rpc *);
void tasvir_handle_msg_rpc_response(tasvir_msg_rpc *);
size_t tasvir_sync_parse_log(const tasvir_area_desc *__restrict, size_t, size_t, int);
size_t tasvir_sync_process_changes(const tasvir_area_desc *__restrict, bool, bool);
int tasvir_sync_internal();

#ifdef TASVIR_DAEMON
int tasvir_init_port();
void tasvir_stats_update();
void tasvir_handle_msg_mem(tasvir_msg_mem *);
void tasvir_service_port_tx();
int tasvir_sync_external();
size_t tasvir_sync_external_area(tasvir_area_desc *);
#endif

#include "utils.h"

#endif /* TASVIR_SRC_TASVIR_TASVIR_H_ */
