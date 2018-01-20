#ifndef _TASVIR__H_
#define _TASVIR__H_
#pragma once

#include <limits.h>
#include <math.h>
#include <mmintrin.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uthash.h>

#ifdef __cplusplus
extern "C" {
#define TASVIR_STATIC_ASSERT static_assert
#else
#define TASVIR_STATIC_ASSERT _Static_assert
#endif

typedef uint64_t tasvir_log_t;
typedef unsigned long tasvir_arg_promo_t;

#define TASVIR_BARRIER_ENTER_US (200)         /* max time to enter sync */
#define TASVIR_STAT_US (1 * 1000 * 1000)      /* stat interval */
#define TASVIR_SYNC_INTERNAL_US (10 * 1000)   /* sync interval */
#define TASVIR_SYNC_EXTERNAL_US (100 * 1000)  /* sync interval */
#define TASVIR_HEARTBEAT_US (1 * 1000 * 1000) /* timer to announce a thread dead */

#define TASVIR_ETH_PROTO (0x88b6)
#define TASVIR_HUGEPAGE_SIZE (size_t)(2 << 20)
#define TASVIR_NR_AREAS_MAX (1024)
#define TASVIR_NR_AREA_LOGS (4)
#define TASVIR_NR_CACHELINES_PER_MSG (21)
#define TASVIR_NR_FN (4096)
#define TASVIR_NR_RPC_ARGS (8)
#define TASVIR_NR_RPC_MSG (65536)
#define TASVIR_NR_NODES_AREA (64)
#define TASVIR_NR_SOCKETS (2)
#define TASVIR_NR_SYNC_JOBS (2048)
#define TASVIR_NR_THREADS_LOCAL (64)
#define TASVIR_RING_SIZE (64)
#define TASVIR_STRLEN_MAX (32)
#define TASVIR_SYNC_JOB_BYTES (size_t)(1 << 21) /* max size of each job */
#define TASVIR_THREAD_DAEMON_IDX (0)

#define __TASVIR_LOG2(x) (31 - __builtin_clz(x | 1))

#define TASVIR_CACHELINE_BYTES (64)
#define TASVIR_LOG_UNIT_BITS (CHAR_BIT * sizeof(tasvir_log_t))
#define TASVIR_SHIFT_BIT (__TASVIR_LOG2(TASVIR_CACHELINE_BYTES)) /* 1 bit per cacheline */
#define TASVIR_SHIFT_BYTE (TASVIR_SHIFT_BIT + __TASVIR_LOG2(CHAR_BIT))
#define TASVIR_SHIFT_UNIT (TASVIR_SHIFT_BYTE + __TASVIR_LOG2(sizeof(tasvir_log_t)))

#define TASVIR_ALIGNMENT (uintptr_t)(1 << TASVIR_SHIFT_UNIT)
#define TASVIR_ALIGNX(x, a) (((uintptr_t)(x) + a - 1) & ~(a - 1))
#define TASVIR_ALIGN(x) TASVIR_ALIGNX(x, TASVIR_ALIGNMENT)

#define TASVIR_SIZE_DATA ((size_t)TASVIR_ALIGN((4UL << 40))) /* must be a power of two; 4TB */
#define TASVIR_SIZE_LOG ((size_t)TASVIR_ALIGN((TASVIR_SIZE_DATA >> TASVIR_SHIFT_BYTE)))
#define TASVIR_SIZE_LOCAL ((size_t)TASVIR_ALIGN((TASVIR_HUGEPAGE_SIZE * 260)))

#define TASVIR_ADDR_BASE ((uintptr_t)(0x0000100000000000UL))
#define TASVIR_ADDR_DATA ((uintptr_t)(TASVIR_ADDR_BASE))
#define TASVIR_ADDR_SHADOW ((uintptr_t)(TASVIR_ADDR_DATA + TASVIR_SIZE_DATA))
#define TASVIR_ADDR_LOG ((uintptr_t)(TASVIR_ADDR_SHADOW + TASVIR_SIZE_DATA))
#define TASVIR_ADDR_LOCAL ((uintptr_t)(TASVIR_ADDR_LOG + TASVIR_SIZE_LOG))
#define TASVIR_ADDR_END ((uintptr_t)(TASVIR_ADDR_LOCAL + TASVIR_SIZE_LOCAL))
#define TASVIR_ADDR_ROOT_DESC ((uintptr_t)(TASVIR_ADDR_SHADOW - TASVIR_HUGEPAGE_SIZE))
#define TASVIR_ADDR_DPDK_BASE ((uintptr_t)(TASVIR_ADDR_END + TASVIR_HUGEPAGE_SIZE))

TASVIR_STATIC_ASSERT(TASVIR_CACHELINE_BYTES, "TASVIR_CACHELINE_BYTES not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_LOG_UNIT_BITS, "TASVIR_LOG_UNIT_BITS not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SHIFT_BIT, "TASVIR_SHIFT_BIT not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SHIFT_BYTE, "TASVIR_SHIFT_BYTE not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SHIFT_UNIT, "TASVIR_SHIFT_UNIT not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SIZE_DATA, "TASVIR_SIZE_DATA not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SIZE_LOG, "TASVIR_SIZE_LOG not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_SIZE_LOCAL, "TASVIR_SIZE_LOCAL not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_BASE, "TASVIR_ADDR_BASE not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_DATA, "TASVIR_ADDR_DATA not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_SHADOW, "TASVIR_ADDR_SHADOW not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_LOG, "TASVIR_ADDR_LOG not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_LOCAL, "TASVIR_ADDR_LOCAL not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_END, "TASVIR_ADDR_END not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_ROOT_DESC, "TASVIR_ADDR_ROOT_DESC not a compile-time const expression.");
TASVIR_STATIC_ASSERT(TASVIR_ADDR_DPDK_BASE, "TASVIR_ADDR_DPDK_BASE not a compile-time const expression.");

struct rte_ring;
struct rte_mempool;

/* typedef uuid_t tasvir_uuid_t; */
typedef char tasvir_str[TASVIR_STRLEN_MAX];
typedef struct { tasvir_str str; } tasvir_str_static;
typedef struct tasvir_fn_info tasvir_fn_info;
typedef struct tasvir_tid tasvir_tid;
typedef struct tasvir_nid tasvir_nid;
typedef struct tasvir_cacheline tasvir_cacheline;
typedef struct tasvir_msg tasvir_msg;
typedef struct tasvir_msg_rpc tasvir_msg_rpc;
typedef struct tasvir_msg_mem tasvir_msg_mem;
typedef struct tasvir_rpc_status tasvir_rpc_status;
typedef struct tasvir_thread tasvir_thread;
typedef struct tasvir_area_desc tasvir_area_desc;
typedef struct tasvir_area_log tasvir_area_log;
typedef struct tasvir_area_user tasvir_area_user;
typedef struct tasvir_area_header tasvir_area_header;
typedef struct tasvir_sync_stats tasvir_sync_stats;
typedef struct tasvir_node tasvir_node;
typedef void (*tasvir_fnptr)(void *, ptrdiff_t *);
typedef void (*tasvir_rpc_cb_fnptr)(tasvir_msg_rpc *);

typedef enum {
    TASVIR_AREA_TYPE_INVALID = 0,
    TASVIR_AREA_TYPE_CONTAINER,
    TASVIR_AREA_TYPE_NODE,
    TASVIR_AREA_TYPE_APP
} tasvir_area_type;

static const char *tasvir_area_type_str[] = {"invalid", "contianer", "node", "app"};

typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_MEM,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

static const char *tasvir_msg_type_str[] = {"invalid", "memory", "rpc_request", "rpc_reply"};

typedef enum {
    TASVIR_RPC_STATUS_INVALID = 0,
    TASVIR_RPC_STATUS_PENDING,
    TASVIR_RPC_STATUS_FAILED,
    TASVIR_RPC_STATUS_DONE
} tasvir_rpc_status_type;

static const char *tasvir_rpc_status_type_str[] = {"invalid", "pending", "failed", "done"};

typedef enum {
    TASVIR_THREAD_TYPE_INVALID = 0,
    TASVIR_THREAD_TYPE_ROOT,
    TASVIR_THREAD_TYPE_DAEMON,
    TASVIR_THREAD_TYPE_APP,
} tasvir_thread_type;

static const char *tasvir_thread_type_str[] = {"invalid", "root", "daemon", "application"};

typedef enum {
    TASVIR_TID_INVALID = 0,
    TASVIR_TID_DEFAULT,
    TASVIR_TID_BROADCAST,
    TASVIR_TID_LOCAL,
    TASVIR_TID_UPDATE
} tasvir_tid_type;

static const char *tasvir_tid_type_str[] = {"invalid", "default", "broadcast", "local", "update"};

struct tasvir_fn_info {
    tasvir_str name;
    tasvir_fnptr fnptr;
    uint32_t fid;
    uint8_t argc;
    int ret_len;
    size_t arg_lens[TASVIR_NR_RPC_ARGS];
    ptrdiff_t arg_offsets[TASVIR_NR_RPC_ARGS];
    UT_hash_handle h_fid;
    UT_hash_handle h_fnptr;
};

struct tasvir_nid {
    struct ether_addr mac_addr;
};

struct tasvir_tid {
    tasvir_nid nid;
    uint16_t idx;
    pid_t pid;
};

struct tasvir_cacheline {
    uint8_t b[TASVIR_CACHELINE_BYTES];
} __attribute__((aligned(TASVIR_CACHELINE_BYTES)));

struct tasvir_msg {
    struct rte_mbuf mbuf;
    uint8_t pad_[RTE_PKTMBUF_HEADROOM];
    struct ether_hdr eh;
    tasvir_tid src_tid;
    tasvir_tid dst_tid;
    tasvir_msg_type type;
    uint16_t id;
    uint64_t time_us;
} __attribute__((__packed__));

struct tasvir_msg_rpc {
    tasvir_msg h;
    tasvir_area_desc *d;
    uint32_t fid;
    uint8_t data[1] __attribute__((aligned(sizeof(tasvir_arg_promo_t)))); /* for compatibility */
} __attribute__((__packed__));

struct tasvir_msg_mem {
    tasvir_msg h;
    void *addr;
    size_t len;
    tasvir_cacheline line[TASVIR_NR_CACHELINES_PER_MSG] __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
} __attribute__((__packed__));

struct tasvir_rpc_status {
    bool do_free;
    uint16_t id;
    tasvir_rpc_status_type status;
    tasvir_msg_rpc *response;
    tasvir_rpc_cb_fnptr cb; /* ignore for now */
};

struct tasvir_thread {
    tasvir_tid tid;
    uint16_t core;
    tasvir_thread_type type;
    bool active;
};

struct tasvir_area_desc {
    tasvir_area_desc *pd;
    tasvir_area_header *h;
    size_t len;
    size_t offset_log_end;
    size_t nr_areas_max;
    tasvir_thread *owner;
    union {
        tasvir_str_static name_static;
        tasvir_str name;
    };
    uint64_t boot_us;
    uint64_t stale_us;
    uint8_t type;
    bool active;
};

struct tasvir_area_log {
    uint64_t version_start;
    uint64_t start_us;
    uint64_t version_end;
    uint64_t end_us;
    tasvir_log_t *data;
};

struct tasvir_area_user {
    tasvir_node *node;
    uint64_t version;
    bool active;
};

struct tasvir_area_header {
    struct {
        bool rw; /* used to id the writer version */
        bool local;
    } private_tag; /* not to be synced */
    tasvir_area_desc *d __attribute__((aligned(1 << TASVIR_SHIFT_BIT)));
    uint64_t version;
    uint64_t update_us;
    size_t nr_areas;
    size_t nr_users;
    bool active;
    tasvir_area_log diff_log[TASVIR_NR_AREA_LOGS];
    tasvir_area_user users[TASVIR_NR_NODES_AREA];
} __attribute__((aligned(TASVIR_CACHELINE_BYTES)));

struct tasvir_sync_stats {
    uint64_t count;
    uint64_t cumtime_us;
    uint64_t cumbytes;
    uint64_t cumbytes_rx;
    uint64_t cumpkts_rx;
};

struct tasvir_node {
    tasvir_nid nid;
    uint32_t heartbeat_us;
    tasvir_thread threads[TASVIR_NR_THREADS_LOCAL];
};

tasvir_area_desc *tasvir_init(uint8_t type, uint16_t core, char *pciaddr);
tasvir_sync_stats tasvir_sync_stats_get(void);
void tasvir_sync_stats_reset(void);
/* FIXME: rpc assumes return value is a ptr */
tasvir_rpc_status *tasvir_rpc(tasvir_area_desc *, tasvir_fnptr, ...);
bool tasvir_rpc_wait(uint64_t timeout_us, void **retval, tasvir_area_desc *, tasvir_fnptr, ...);
int tasvir_rpc_register(tasvir_fn_info *);
bool tasvir_service() __attribute__((hot));
bool tasvir_service_wait(uint64_t timeout_us) __attribute__((hot));
tasvir_area_desc *tasvir_new(tasvir_area_desc d);
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer);
tasvir_area_desc *tasvir_attach_wait(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer,
                                     uint64_t timeout_us);
int tasvir_detach(tasvir_area_desc *d);
int tasvir_delete(tasvir_area_desc *d);
bool tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner);

static inline void *tasvir_data(tasvir_area_desc *d) { return d->h + 1; }

/* log impl */
static inline void *__attribute__((hot)) tasvir_log2data(const void *log) {
    return (uint8_t *)((uintptr_t)log << TASVIR_SHIFT_BYTE) +
           (TASVIR_ADDR_DATA - (TASVIR_ADDR_LOG << TASVIR_SHIFT_BYTE));
}

static inline uint64_t __attribute__((hot)) tasvir_data2log_bit_offset(const void *data) {
    return _pext_u64((uintptr_t)data, ((1UL << TASVIR_SHIFT_UNIT) - 1) & (~0UL << TASVIR_SHIFT_BIT));
}

static inline tasvir_log_t *__attribute__((hot)) tasvir_data2log(const void *data) {
    return (tasvir_log_t *)TASVIR_ADDR_LOG +
           _pext_u64((uintptr_t)data, (TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_UNIT));
}

static inline void *__attribute__((hot)) tasvir_data2shadow(void *data) {
    return (uint8_t *)data + TASVIR_ADDR_SHADOW - TASVIR_ADDR_DATA;
}

static inline void __attribute__((hot)) tasvir_log_write(const void *data, size_t len) {
    const void *data_end = (const uint8_t *)data + len;
    tasvir_log_t *log = tasvir_data2log(data);
    tasvir_log_t *data_end_log = tasvir_data2log(data_end);
    uint64_t bit_start = tasvir_data2log_bit_offset(data);
    uint64_t bit_end = tasvir_data2log_bit_offset(data_end);

    /*
    fprintf(stderr, "%14d %-22.22s %p-%p (%luB) log:%p-%p bit:%lu-%lu\n", 0, "tasvir_log_write", data, data_end, len,
            (void *)log, (void *)data_end_log, bit_start, bit_end);
    */

    if (log == data_end_log) {
        *log |= (~0UL >> bit_start) & ((1L << 63) >> bit_end);
    } else {
        *log |= ~0UL >> bit_start;
        do {
            log++;
            *log = ~0UL;
        } while (log < data_end_log);
        *log |= (1L << 63) >> bit_end;
    }
}

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
