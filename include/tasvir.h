#ifndef _TASVIR__H_
#include <limits.h>
#include <math.h>
#include <mmintrin.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <rte_mbuf.h>
#ifdef __cplusplus
#include <atomic>
using namespace std;
#else
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uthash.h>

typedef uint64_t tasvir_log_t;

#define TASVIR_SYNC_US (100000)              // sync interval
#define TASVIR_STAT_US (1 * 1000 * 1000)     // stat interval
#define TASVIR_BARRIER_ENTER_US (200)        // max time to enter sync
#define TASVIR_BARRIER_EXIT_US (100 * 1000)  // max time sync takes
#define TASVIR_HEARTBEAT_US (100 * 1000)     // timer to announce a thread dead

#define TASVIR_SYNC_JOB_BYTES (size_t)(1 << 20)  // max size of each job
#define TASVIR_SYNC_NR_JOBS (512)
#define TASVIR_HUGEPAGE_SIZE (size_t)(2 << 20)
// #define TASVIR_ETH_PROTO (0x88b6)
#define TASVIR_STRLEN_MAX (32)
#define TASVIR_NR_FN (4096)
#define TASVIR_NR_RPC_ARGS (8)
#define TASVIR_NR_RPC_MSG (65536)
#define TASVIR_RING_SIZE (256)
#define TASVIR_NR_THREADS_AREA (128)
#define TASVIR_NR_THREADS_LOCAL (64)
#define TASVIR_THREAD_DAEMON_IDX (0)

#define __TASVIR_LOG2(x) (31 - __builtin_clz(x | 1))
#define TASVIR_CACHELINE_BYTES (64)
#define TASVIR_SHIFT_BIT (6)  // 1 bit per cacheline
#define TASVIR_SHIFT_BYTE (TASVIR_SHIFT_BIT + __TASVIR_LOG2(CHAR_BIT))
#define TASVIR_SHIFT_UNIT (TASVIR_SHIFT_BYTE + __TASVIR_LOG2(sizeof(tasvir_log_t)))
#define TASVIR_ALIGNMENT (uintptr_t)(TASVIR_SHIFT_UNIT >= 12 ? (1 << TASVIR_SHIFT_UNIT) : 4096)
#define TASVIR_ALIGNX(x, a) ((uintptr_t)(x + a - 1) & ~(a - 1))
#define TASVIR_ALIGN(x) TASVIR_ALIGNX((uintptr_t)x, TASVIR_ALIGNMENT)
#define TASVIR_SIZE_DATA (size_t) TASVIR_ALIGN((4UL << 40))  // must be a power of two; 4TB
#define TASVIR_SIZE_LOG (size_t) TASVIR_ALIGN((TASVIR_SIZE_DATA >> TASVIR_SHIFT_BYTE))
#define TASVIR_SIZE_LOCAL (size_t) TASVIR_ALIGN(TASVIR_HUGEPAGE_SIZE)
#define TASVIR_ADDR_BASE (void *)(0x0000100000000000UL)
#define TASVIR_ADDR_DATA (void *)(TASVIR_ADDR_BASE)
#define TASVIR_ADDR_SHADOW (void *)((uint8_t *)TASVIR_ADDR_DATA + TASVIR_SIZE_DATA)
#define TASVIR_ADDR_LOG (void *)((uint8_t *)TASVIR_ADDR_SHADOW + TASVIR_SIZE_DATA)
#define TASVIR_ADDR_LOCAL (void *)((uint8_t *)TASVIR_ADDR_LOG + TASVIR_SIZE_LOG)
#define TASVIR_ADDR_END (void *)((uint8_t *)TASVIR_ADDR_LOCAL + TASVIR_SIZE_LOCAL)
#define TASVIR_ADDR_ROOT_DESC (void *)((uint8_t *)TASVIR_ADDR_SHADOW - TASVIR_HUGEPAGE_SIZE)
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
    uint64_t last_sync_start;
    uint64_t last_sync_end;
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
    tasvir_sync_job jobs[TASVIR_SYNC_NR_JOBS];
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

/* log impl */
static inline void *tasvir_addr_data(void *addr_log) {
    ptrdiff_t offset = (uint8_t *)TASVIR_ADDR_DATA - (uint8_t *)((ptrdiff_t)TASVIR_ADDR_LOG << TASVIR_SHIFT_BYTE);
    return (uint8_t *)(((ptrdiff_t)addr_log) << TASVIR_SHIFT_BYTE) + offset;
}

static inline uint64_t tasvir_addr_log_bit_offset(void *addr) {
    uint64_t mask = ((1UL << TASVIR_SHIFT_UNIT) - 1) & (~0UL << TASVIR_SHIFT_BIT);
    return _pext_u64((uintptr_t)addr, mask);
}

static inline tasvir_log_t *tasvir_addr_log(void *addr) {
    uint64_t mask = (TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_UNIT);
    return (tasvir_log_t *)TASVIR_ADDR_LOG + _pext_u64((uintptr_t)addr, mask);
}

static inline void *tasvir_addr_shadow(void *addr) {
    ptrdiff_t offset = (uint8_t *)TASVIR_ADDR_SHADOW - (uint8_t *)TASVIR_ADDR_DATA;
    return (uint8_t *)addr + offset;
}

static inline void tasvir_log_write(void *addr, size_t len) {
    void *addr_end = (uint8_t *)addr + len;
    tasvir_log_t *addr_log = tasvir_addr_log(addr);
    tasvir_log_t *addr_end_log = tasvir_addr_log(addr_end);
    uint64_t bit_start = tasvir_addr_log_bit_offset(addr);
    uint64_t bit_end = tasvir_addr_log_bit_offset(addr_end);
    /* fprintf(stderr, "%14d %-22.22s %p-%p (%luB) log:%p-%p bit:%lu-%lu\n", 0, "tasvir_log_write", addr, addr_end, len,
       (void *)addr_log, (void *)addr_end_log, bit_start, bit_end); */

    if (addr_log == addr_end_log) {
        *addr_log |= (~0UL >> bit_start) & ((1L << 63) >> bit_end);
    } else {
        *addr_log |= ~0UL >> bit_start;
        do {
            addr_log++;
            *addr_log = ~0UL;
        } while (unlikely(addr_log < addr_end_log));
        *addr_log |= (1L << 63) >> bit_end;
    }

    /*
    uint64_t mask_v[2] = {0, 0};
    tasvir_log_t *addr_log_aligned = (tasvir_log_t *)((uintptr_t)addr_log & ~0xfUL);
    mask_v[addr_log - addr_log_aligned] = (~0UL >> bit_start) & ((1L << 63) >> bit_end);
    __m128i m = _mm_stream_load_si128((const __m128i *)(addr_log_aligned));
    m = _mm_or_si128(m, _mm_set_epi64x(mask_v[1], mask_v[0]));
    _mm_stream_si128((__m128i *)addr_log_aligned, m);
    */
}

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
