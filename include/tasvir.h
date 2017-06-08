#ifndef _TASVIR__H_
#include <limits.h>
#include <mmintrin.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
//#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uthash.h>
//#include <uuid/uuid.h>

#include <rte_mbuf.h>

typedef uint64_t tasvir_log_t;

#define TASVIR_SYNC_US (100000)                     // sync interval
#define TASVIR_STAT_US (1 * 1000 * 1000)            // stat interval
#define TASVIR_BARRIER_ENTER_US (200)               // max time to enter sync
#define TASVIR_BARRIER_EXIT_US (100 * 1000)         // max time sync takes
#define TASVIR_HEARTBEAT_US (100 * 1000)            // timer to announce a thread dead
#define TASVIR_SYNC_JOB_BYTES (10UL * 1024 * 1024)  // max size of each job
#define TASVIR_HUGEPAGE_SIZE (2097152)

// #define TASVIR_ETH_PROTO (0x88b6)
#define TASVIR_STRLEN_MAX (32)
#define TASVIR_NR_FN (4096)
#define TASVIR_NR_RPC_ARGS (8)
#define TASVIR_NR_RPC_MSG (65535)
#define TASVIR_RING_SIZE (256)
#define TASVIR_NR_THREADS_AREA (128)
#define TASVIR_NR_THREADS_LOCAL (64)
#define TASVIR_THREAD_DAEMON_IDX (0)

#define TASVIR_CACHELINE_BYTES (64)
#define TASVIR_SHIFT_BIT (6)                      // 1 bit per cacheline
#define TASVIR_SHIFT_BYTE (TASVIR_SHIFT_BIT + 3)  // 1 bit per cacheline
#define TASVIR_SHIFT_UNIT (TASVIR_SHIFT_BYTE + 3) /* log2(sizeof(tasvir_log_t)) == 3 */
#define TASVIR_LOG_BIT (1 << TASVIR_SHIFT_BIT)
#define TASVIR_LOG_UNIT (1 << TASVIR_SHIFT_UNIT)
#define TASVIR_ALIGNMENT (TASVIR_LOG_UNIT)
#define TASVIR_ALIGNX(x, a) ((uintptr_t)(x + a - 1) & ~(a - 1))
#define TASVIR_ALIGN(x) TASVIR_ALIGNX((uint8_t *)x, TASVIR_ALIGNMENT)
#define TASVIR_SIZE_DESC (4096)
#define TASVIR_SIZE_ROOT_CONTAINER (TASVIR_HUGEPAGE_SIZE)
#define TASVIR_SIZE_LOCAL_STRUCT (TASVIR_HUGEPAGE_SIZE)
#define TASVIR_SIZE_GLOBAL (4UL * 1024 * 1024 * 1024 * 1024)  // 4TB
#define TASVIR_SIZE_LOG TASVIR_ALIGNX(TASVIR_SIZE_GLOBAL / (TASVIR_LOG_BIT * CHAR_BIT), TASVIR_HUGEPAGE_SIZE)
#define TASVIR_SIZE_LOCAL (TASVIR_SIZE_LOCAL_STRUCT + TASVIR_SIZE_LOG + TASVIR_SIZE_GLOBAL)
#define TASVIR_SIZE_WHOLE (TASVIR_SIZE_LOCAL + TASVIR_SIZE_GLOBAL)
#define TASVIR_ADDR_BASE (void *)(0x0000100000000000UL)
#define TASVIR_ADDR_LOCAL (void *)TASVIR_ADDR_BASE
#define TASVIR_ADDR_LOG \
    (void *)TASVIR_ALIGNX((uint8_t *)TASVIR_ADDR_LOCAL + TASVIR_SIZE_LOCAL_STRUCT, TASVIR_HUGEPAGE_SIZE)
#define TASVIR_ADDR_SHADOW (void *)((uint8_t *)TASVIR_ADDR_LOG + TASVIR_SIZE_LOG)
#define TASVIR_ADDR_GLOBAL (void *)((uint8_t *)TASVIR_ADDR_SHADOW + TASVIR_SIZE_GLOBAL) /* lower bound */
#define TASVIR_ADDR_END (void *)((uint8_t *)TASVIR_ADDR_GLOBAL + TASVIR_SIZE_GLOBAL)
#define TASVIR_ADDR_ROOT_DESC (void *)((uint8_t *)TASVIR_ADDR_END - TASVIR_SIZE_DESC)
#define TASVIR_DPDK_ADDR_BASE (void *)((uint8_t *)TASVIR_ADDR_END + TASVIR_HUGEPAGE_SIZE)

#ifdef __cplusplus
extern "C" {
#endif

struct rte_ring;
struct rte_mempool;

// typedef uuid_t tasvir_uuid_t;
typedef char tasvir_str[TASVIR_STRLEN_MAX];
typedef struct { tasvir_str str; } tasvir_str_static;
typedef struct tasvir_fn_info tasvir_fn_info;
typedef struct tasvir_thread_id tasvir_thread_id;
typedef struct tasvir_node_id tasvir_node_id;
typedef struct tasvir_msg_header tasvir_msg_header;
typedef struct tasvir_msg_rpc tasvir_msg_rpc;
typedef struct tasvir_rpc_status tasvir_rpc_status;
typedef struct tasvir_thread tasvir_thread;
typedef struct tasvir_area_desc tasvir_area_desc;
typedef struct tasvir_area_header tasvir_area_header;
typedef struct tasvir_container tasvir_container;
typedef struct tasvir_sync_job tasvir_sync_job;
typedef struct tasvir_local_dstate tasvir_local_dstate;
typedef struct tasvir_local_istate tasvir_local_istate;
typedef struct tasvir_tls_state tasvir_tls_state;
typedef struct tasvir_local tasvir_local;
typedef struct tasvir_node tasvir_node;
typedef void (*tasvir_fnptr)(void *, void **);
typedef void (*tasvir_rpc_cb_fnptr)(tasvir_msg_rpc *);

typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_DATA,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

typedef enum {
    TASVIR_RPC_STATUS_INVALID = 0,
    TASVIR_RPC_STATUS_PENDING,
    TASVIR_RPC_STATUS_FAILED,
    TASVIR_RPC_STATUS_DONE
} tasvir_rpc_status_type;

typedef enum {
    TASVIR_THREAD_TYPE_INVALID = 0,
    TASVIR_THREAD_TYPE_ROOT,
    TASVIR_THREAD_TYPE_DAEMON,
    TASVIR_THREAD_TYPE_APP
} tasvir_thread_type;

typedef enum {
    TASVIR_THREAD_STATUS_INVALID = 0,
    TASVIR_THREAD_STATUS_DEAD,
    TASVIR_THREAD_STATUS_BOOTING,
    TASVIR_THREAD_STATUS_RUNNING
} tasvir_thread_status;

typedef enum {
    TASVIR_AREA_TYPE_INVALID = 0,
    TASVIR_AREA_TYPE_CONTAINER,
    TASVIR_AREA_TYPE_NODE,
    TASVIR_AREA_TYPE_APP
} tasvir_area_type;

struct tasvir_fn_info {
    tasvir_str name;
    tasvir_fnptr fnptr;
    uint32_t fid;
    uint8_t argc;
    int ret_len;
    size_t arg_lens[TASVIR_NR_RPC_ARGS];
    UT_hash_handle h_fid;
    UT_hash_handle h_fnptr;
};

struct tasvir_node_id {
    uint8_t ethaddr[ETHER_ADDR_LEN];
    // uint32_t machine_id;
};

struct tasvir_thread_id {
    tasvir_node_id node_id;
    uint16_t idx;
    pid_t pid;
};

struct tasvir_msg_header {
    struct rte_mbuf mbuf;
    struct ether_header eh;
    struct iphdr ih;
    struct udphdr uh;
    /* TODO: add ip and udp header so that NIC takes care of checksum */
    tasvir_thread_id src_id;
    tasvir_thread_id dst_id;
    tasvir_msg_type type;
    uint16_t id;
    uint64_t time_us;
};

struct tasvir_msg_rpc {
    tasvir_msg_header h;
    uint32_t fid;
    void *arg_ptrs[TASVIR_NR_RPC_ARGS];
    uint8_t data[1] __attribute__((aligned(sizeof(int))));  // for compatibility
} __attribute__((__packed__));

struct tasvir_rpc_status {
    bool do_free;
    uint16_t id;
    tasvir_rpc_status_type status;
    tasvir_msg_rpc *response;
    tasvir_rpc_cb_fnptr cb;  // ignore for now
};

struct tasvir_thread {
    tasvir_thread_id id;
    uint16_t core;
    tasvir_thread_type type;
    tasvir_thread_status status;
};

struct tasvir_area_desc {
    tasvir_area_desc *pd;
    tasvir_area_header *h;
    size_t len;
    uint8_t type;
    tasvir_thread *owner;
    tasvir_str name;
    bool active;
};

struct tasvir_area_header {
    tasvir_area_desc *d;
    uint64_t version;
    uint64_t stale_us;
    uint64_t update_us;
    uint64_t boot_us;
    size_t nr_users;
    tasvir_thread *users[TASVIR_NR_THREADS_AREA];
    uint8_t data[1] __attribute__((aligned(TASVIR_ALIGNMENT)));  // [1] for compatibility
} __attribute__((aligned(TASVIR_ALIGNMENT)));

struct tasvir_container {
    size_t len;
    size_t nr_areas;
    tasvir_area_desc descs[1];  // for compatibility
};

struct tasvir_local_dstate {  // daemon state
    uint64_t last_stat;
    uint64_t last_sync;
    uint64_t sync_count;
    uint64_t sync_cumtime_us;
    uint64_t sync_cumbytes;
} __attribute__((aligned(8)));

struct tasvir_sync_job {
    uint64_t version;
    tasvir_area_header *h_dst;
    tasvir_area_header *h_src;
    uint8_t *addr_dst;
    uint8_t *addr_src;
    tasvir_log_t *addr_log;
    size_t len;
};

struct tasvir_local_istate {  // thread state
    uint64_t update_us;
    struct rte_ring *ring_tx;
    struct rte_ring *ring_rx;
    bool sync;
    size_t nr_jobs;
    tasvir_sync_job jobs[128];
    size_t sync_cumbytes;
} __attribute__((aligned(8)));

struct tasvir_tls_state {  // thread-internal state
    tasvir_area_desc *node_desc;
    tasvir_area_desc *root_desc;

    tasvir_local *local;
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

struct tasvir_local {
    uint64_t time_us;
    uint64_t tsc_hz;
    struct rte_mempool *mp;
    atomic_uint barrier_entry;
    atomic_uint barrier_exit;
    pthread_mutex_t mutex_boot;
    pthread_mutexattr_t mutex_attr;
    struct rte_ring *ring_ext_tx;
    struct rte_ring *ring_ext_rx;
    tasvir_local_dstate dstate;                           // daemon-specific state
    tasvir_local_istate istate[TASVIR_NR_THREADS_LOCAL];  // thread state
} __attribute__((aligned(8)));

struct tasvir_node {
    tasvir_node_id id;
    uint32_t heartbeat_us;
    size_t nr_threads;
    tasvir_thread threads[TASVIR_NR_THREADS_LOCAL];
};

tasvir_area_desc *tasvir_init(uint16_t core, uint8_t type);
tasvir_rpc_status *tasvir_rpc_async(tasvir_thread *, tasvir_fnptr, ...);
void *tasvir_rpc_sync(tasvir_thread *, uint64_t timeout, tasvir_fnptr, ...);
int tasvir_rpc_register(tasvir_fn_info *);
void tasvir_service();
tasvir_area_desc *tasvir_new(tasvir_area_desc d, uint64_t stale_us, size_t container_len);
int tasvir_delete(tasvir_area_desc *d);
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, char *name);
int tasvir_detach(tasvir_area_desc *d);
void tasvir_set_owner(tasvir_area_desc *d, tasvir_thread *owner);
// void tasvir_log_write_ext(void *addr, size_t len);

/* naive log impl */

static inline void *tasvir_addr_shadow(void *addr) {
    return (uint8_t *)addr - ((uint8_t *)TASVIR_ADDR_GLOBAL - (uint8_t *)TASVIR_ADDR_SHADOW);
}

static inline tasvir_log_t *tasvir_addr_log(void *addr) {
    ptrdiff_t addr_rel = (uint8_t *)addr - (uint8_t *)TASVIR_ADDR_GLOBAL;
    return (tasvir_log_t *)((uint8_t *)TASVIR_ADDR_LOG + (addr_rel >> TASVIR_SHIFT_BYTE));
}

static inline void *tasvir_addr_from_log(tasvir_log_t *addr_log) {
    ptrdiff_t addr_rel = (uint8_t *)addr_log - (uint8_t *)TASVIR_ADDR_LOG;
    return (uint8_t *)TASVIR_ADDR_GLOBAL + (addr_rel << TASVIR_SHIFT_BYTE);
}

static inline void tasvir_log_write(void *addr, size_t len) {
    tasvir_log_t *addr_log = tasvir_addr_log(addr);
    const int log_unit_bits_minus_one = CHAR_BIT * sizeof(tasvir_log_t) - 1;
    int log_offset_bit = (ptrdiff_t)addr >> TASVIR_SHIFT_BIT;
    int log_offset_bit_end = ((ptrdiff_t)addr + len) >> TASVIR_SHIFT_BIT;
    int nbits = 1 + log_offset_bit_end - log_offset_bit;
    log_offset_bit &= log_unit_bits_minus_one;
    int nbits_this = ((nbits + log_offset_bit - 1) & log_unit_bits_minus_one) + 1 - log_offset_bit;
    *addr_log |= ((uint64_t)((1L << 63) >> (nbits_this - 1))) >> log_offset_bit;
    nbits -= nbits_this;
    // fprintf(stderr, "addr=%p len=%lu offset=%d nbits=%d nbits_this=%d\n", addr, len, log_offset_bit, nbits,
    // nbits_this);

    while (nbits > 0) {
        ++addr_log;
        nbits_this = 1 + ((nbits - 1) & log_unit_bits_minus_one);
        *addr_log |= (1L << 63) >> (nbits_this - 1);
        nbits -= nbits_this;
    }
}

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
