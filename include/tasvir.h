/**
 * @file
 *   tasvir.h
 * @brief
 *   Function prototypes for Tasvir.
 *
 * @author
 *   Amin Tootoonchian
 */

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

#define TASVIR_BARRIER_ENTER_US (10)        /**< Time (microseconds) to wait in the sync barrier */
#define TASVIR_STAT_US (1 * 1000 * 1000)    /**< Time (microseconds) between updating and printing average statistics */
#define TASVIR_SYNC_INTERNAL_US (50 * 1000) /**< Time (microseconds) between internal synchronization intervals */
#define TASVIR_SYNC_EXTERNAL_US (250 * 1000)  /**< Time (microseconds) between external synchronization intervals */
#define TASVIR_HEARTBEAT_US (1 * 1000 * 1000) /**< Time (microseconds) after which a node may be announced dead */

#define TASVIR_ETH_PROTO (0x88b6)              /**< Ethernet protocol number to distinguish Tasvir traffic */
#define TASVIR_HUGEPAGE_SIZE (size_t)(2 << 20) /**< Size of the huge pages to use */
#define TASVIR_NR_AREAS_MAX (1024)             /**< Maximum number of areas */
#define TASVIR_NR_AREA_LOGS (4)                /**< Number of logs (time intervals) to maintain per area */
#define TASVIR_NR_CACHELINES_PER_MSG (21)      /**< Number of cachelines that fit in a single Tasvir message */
#define TASVIR_NR_FN (4096)                    /**< Maximum number of RPC functions */
#define TASVIR_NR_RPC_ARGS (8)                 /**< Maximum number of RPC function arguments */
#define TASVIR_NR_RPC_MSG (64 * 1024)          /**< Maximum number of outstanding RPC messages */
#define TASVIR_NR_NODES_AREA (64)              /**< Maximum number of nodes in Tasvir */
#define TASVIR_NR_SOCKETS (2)                  /**< Maximum number of CPU sockets per node */
#define TASVIR_NR_SYNC_JOBS (2048)             /**< Maximum number of internal sync jobs */
#define TASVIR_NR_THREADS_LOCAL (64)           /**< Maximum number of local threads */
#define TASVIR_PKT_BURST (32)                  /**< Packet burst size to use for I/O */
#define TASVIR_RING_SIZE (256)                 /**< Maximum size (bytes) of ring for internal I/O */
#define TASVIR_RING_EXT_SIZE (2048)            /**< Maximum size (bytes) of ring for external I/O */
#define TASVIR_STRLEN_MAX (32)                 /**< Maximum size (bytes) of strings */
#define TASVIR_THREAD_DAEMON_IDX (0)           /**< Local thread index for the daemon thread */

#define __TASVIR_LOG2(x) (31 - __builtin_clz(x | 1)) /**< Compile-time log2 for numbers that are power of two */

#define TASVIR_CACHELINE_BYTES (64)                                    /**< Cache line size (bytes) */
#define TASVIR_LOG_UNIT_BITS (CHAR_BIT * sizeof(tasvir_log_t))         /**< Number of bits in each log unit */
#define TASVIR_SHIFT_BIT (__TASVIR_LOG2(TASVIR_CACHELINE_BYTES))       /**<  */
#define TASVIR_SHIFT_BYTE (TASVIR_SHIFT_BIT + __TASVIR_LOG2(CHAR_BIT)) /**<  */
#define TASVIR_SHIFT_UNIT (TASVIR_SHIFT_BYTE + __TASVIR_LOG2(sizeof(tasvir_log_t))) /**<  */

#define TASVIR_ALIGNMENT (uintptr_t)(1 << TASVIR_SHIFT_UNIT)      /**< The default area alignment unit for Tasvir */
#define TASVIR_ALIGNX(x, a) (((uintptr_t)(x) + a - 1) & ~(a - 1)) /**< Align address/size x per alignment a */
#define TASVIR_ALIGN(x) TASVIR_ALIGNX(x, TASVIR_ALIGNMENT)        /**< Align address/size x per TASVIR_ALIGNMENT */

#define TASVIR_SIZE_DATA \
    ((size_t)TASVIR_ALIGN((4UL << 40))) /**< Size (bytes) of the Tasvir data region (must be a power of two) */
#define TASVIR_SIZE_LOG \
    ((size_t)TASVIR_ALIGN((TASVIR_SIZE_DATA >> TASVIR_SHIFT_BYTE))) /**< Size (bytes) of the log region */
#define TASVIR_SIZE_LOCAL \
    ((size_t)TASVIR_ALIGN((TASVIR_HUGEPAGE_SIZE * 260))) /**< Size (bytes) of the local control region */

#define TASVIR_ADDR_BASE ((uintptr_t)(0x0000100000000000UL)) /**< The base virtual address */
#define TASVIR_ADDR_DATA ((uintptr_t)(TASVIR_ADDR_BASE))     /**< The base virtual address for the data region */
#define TASVIR_ADDR_SHADOW \
    ((uintptr_t)(TASVIR_ADDR_DATA + TASVIR_SIZE_DATA)) /**< The base virtual address for the shadow region */
#define TASVIR_ADDR_LOG \
    ((uintptr_t)(TASVIR_ADDR_SHADOW + TASVIR_SIZE_DATA)) /**< The base virtual address for the log region */
#define TASVIR_ADDR_LOCAL \
    ((uintptr_t)(TASVIR_ADDR_LOG + TASVIR_SIZE_LOG)) /**< The base virtual address for the local control region */
#define TASVIR_ADDR_END ((uintptr_t)(TASVIR_ADDR_LOCAL + TASVIR_SIZE_LOCAL)) /**< The end virtual address */
#define TASVIR_ADDR_ROOT_DESC \
    ((uintptr_t)(TASVIR_ADDR_SHADOW - TASVIR_HUGEPAGE_SIZE)) /**< The base virtual address for the root descriptor */
#define TASVIR_ADDR_DPDK_BASE \
    ((uintptr_t)(TASVIR_ADDR_END + TASVIR_HUGEPAGE_SIZE)) /**< The end virtual address for DPDK */

#define TASVIR_OFFSET_SHADOW (TASVIR_ADDR_SHADOW - TASVIR_ADDR_DATA)
#define TASVIR_OFFSET_LOG (TASVIR_ADDR_LOG - TASVIR_ADDR_DATA)

#define TASVIR_BITMASK_LOG_BIT ((TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_BIT))
#define TASVIR_BITMASK_LOG_BYTE ((TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_BYTE))
#define TASVIR_BITMASK_LOG_UNIT ((TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_UNIT))
#define TASVIR_BITMASK_LOG_OFFSET (((1UL << TASVIR_SHIFT_UNIT) - 1) & (~0UL << TASVIR_SHIFT_BIT))

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

typedef uint8_t tasvir_cacheline[TASVIR_CACHELINE_BYTES];
typedef char tasvir_str[TASVIR_STRLEN_MAX];
typedef struct { tasvir_str str; } tasvir_str_static;
typedef bool (*tasvir_fnptr)(void *, ptrdiff_t *);
typedef struct tasvir_msg_rpc tasvir_msg_rpc;
typedef void (*tasvir_rpc_cb_fnptr)(tasvir_msg_rpc *);
typedef struct tasvir_area_desc tasvir_area_desc;
typedef struct tasvir_area_header tasvir_area_header;

/**
 *
 */
typedef enum {
    TASVIR_AREA_TYPE_INVALID = 0,
    TASVIR_AREA_TYPE_CONTAINER,
    TASVIR_AREA_TYPE_NODE,
    TASVIR_AREA_TYPE_APP
} tasvir_area_type;

static const char *tasvir_area_type_str[] = {"invalid", "contianer", "node", "app"};

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

static const char *tasvir_msg_type_str[] = {"invalid", "memory", "rpc_oneway", "rpc_request", "rpc_reply"};

/**
 *
 */
typedef enum {
    TASVIR_RPC_STATUS_INVALID = 0,
    TASVIR_RPC_STATUS_PENDING,
    TASVIR_RPC_STATUS_FAILED,
    TASVIR_RPC_STATUS_DONE
} tasvir_rpc_status_type;

static const char *tasvir_rpc_status_type_str[] = {"invalid", "pending", "failed", "done"};

/**
 *
 */
typedef enum {
    TASVIR_THREAD_TYPE_INVALID = 0,
    TASVIR_THREAD_TYPE_ROOT,
    TASVIR_THREAD_TYPE_DAEMON,
    TASVIR_THREAD_TYPE_APP,
} tasvir_thread_type;

static const char *tasvir_thread_type_str[] = {"invalid", "root", "daemon", "application"};

/**
 *
 */
typedef enum {
    TASVIR_TID_INVALID = 0,
    TASVIR_TID_DEFAULT,
    TASVIR_TID_BROADCAST,
    TASVIR_TID_LOCAL,
    TASVIR_TID_UPDATE
} tasvir_tid_type;

static const char *tasvir_tid_type_str[] = {"invalid", "default", "broadcast", "local", "update"};

/**
 *
 */
typedef struct tasvir_fn_info {
    tasvir_str name;
    tasvir_fnptr fnptr;
    uint32_t fid;
    uint8_t oneway;
    uint8_t argc;
    int ret_len;
    size_t arg_lens[TASVIR_NR_RPC_ARGS];
    ptrdiff_t arg_offsets[TASVIR_NR_RPC_ARGS];
    UT_hash_handle h_fid;
    UT_hash_handle h_fnptr;
} tasvir_fn_info;

/**
 *
 */
typedef struct tasvir_nid { struct ether_addr mac_addr; } tasvir_nid;

/**
 *
 */
typedef struct tasvir_tid {
    tasvir_nid nid;
    uint16_t idx;
    pid_t pid;
} tasvir_tid;

/**
 *
 */
typedef struct tasvir_msg {
    struct rte_mbuf mbuf;
    uint8_t pad_[RTE_PKTMBUF_HEADROOM];
    struct ether_hdr eh;
    tasvir_tid src_tid;
    tasvir_tid dst_tid;
    tasvir_msg_type type;
    uint16_t id;
    uint64_t time_us;
} __attribute__((__packed__)) tasvir_msg;

/**
 *
 */
typedef struct tasvir_msg_rpc {
    tasvir_msg h;
    tasvir_area_desc *d;
    uint32_t fid;
    uint8_t data[1] __attribute__((aligned(sizeof(tasvir_arg_promo_t)))); /* for compatibility */
} __attribute__((__packed__)) tasvir_msg_rpc;

/**
 *
 */
typedef struct tasvir_msg_mem {
    tasvir_msg h;
    tasvir_area_desc *d;
    void *addr;
    size_t len;
    bool last;
    tasvir_cacheline line[TASVIR_NR_CACHELINES_PER_MSG] __attribute__((aligned(TASVIR_CACHELINE_BYTES)));
} __attribute__((__packed__)) tasvir_msg_mem;
TASVIR_STATIC_ASSERT(sizeof(tasvir_msg_mem) - sizeof(struct rte_mbuf) - RTE_PKTMBUF_HEADROOM < 1518,
                     "sizeof(tasvir_msg_mem) exceeds ethernet MTU.");

/**
 *
 */
typedef struct tasvir_rpc_status {
    bool do_free;
    uint16_t id;
    tasvir_rpc_status_type status;
    tasvir_msg_rpc *response;
    tasvir_rpc_cb_fnptr cb; /* ignore for now */
} tasvir_rpc_status;

/**
 *
 */
typedef struct tasvir_thread {
    tasvir_tid tid;
    uint16_t core;
    tasvir_thread_type type;
    bool active;
} tasvir_thread;

/**
 *
 */
typedef struct tasvir_node {
    tasvir_nid nid;
    uint32_t heartbeat_us;
    tasvir_thread threads[TASVIR_NR_THREADS_LOCAL];
} tasvir_node;

/**
 *
 */
typedef struct tasvir_area_desc {
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
    uint64_t sync_int_us;
    uint64_t sync_ext_us;
    uint8_t type;
    bool active;
} tasvir_area_desc;

/**
 *
 */
typedef struct tasvir_area_log {
    uint64_t version_start;
    uint64_t start_us;
    uint64_t version_end;
    uint64_t end_us;
    tasvir_log_t *data;
} tasvir_area_log;

/**
 *
 */
typedef struct tasvir_area_header {
    struct {
        bool rw; /* used to id the writer version */
        bool local;
        bool external_sync_pending;
    } private_tag; /* not to be synced */
    tasvir_area_desc *d __attribute__((aligned(1 << TASVIR_SHIFT_BIT)));
    uint64_t version;
    uint64_t update_us;
    size_t nr_areas;
    size_t nr_users;
    bool active;
    tasvir_area_log diff_log[TASVIR_NR_AREA_LOGS];
    struct {
        tasvir_node *node;
        uint64_t version;
        bool active;
    } users[TASVIR_NR_NODES_AREA];
} __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_area_header;

/**
 *
 */
typedef struct tasvir_sync_stats {
    uint64_t count;
    uint64_t failed;
    uint64_t cumtime_us;
    uint64_t cumbytes;
    uint64_t cumbytes_rx;
    uint64_t cumpkts_rx;
    uint64_t cumbytes_tx;
    uint64_t cumpkts_tx;
} tasvir_sync_stats;

/**
 * @brief
 *   Initialize Tasvir.
 *
 * @param type
 *   The type of thread: a daemon, a root daemon, or a regular application.
 * @param core
 *   The core to run this thread on.
 * @param pciaddr
 *   The PCI address of the NIC to use for network communication in BDF format.
 *   Pass NULL for application threads.
 * @return
 *   The root area descriptor.
 * @note
 *   Must be called very early in program execution and before any other interaction with Tasvir.
 * @note
 *   Each application thread that interacts with Tasvir-backed memory must call this function.
 */
tasvir_area_desc *tasvir_init(tasvir_thread_type type, uint16_t core, char *pciaddr);

/**
 * @brief
 *   Get a copy of internally collected synchronization statistics.
 *
 * @note
 *   Mainly used for benchmarking purposes.
 */
tasvir_sync_stats tasvir_sync_stats_get(void);

/**
 * @brief
 *   Reset internally maintained statistics.
 *
 * @note
 *   Mainly used for benchmarking purposes.
 */
void tasvir_sync_stats_reset(void);

/**
 * @brief
 *   Initiate an RPC call.
 *
 * @param d
 *   The area this call must be executed on.
 * @param fnptr
 *   The function to invoke.
 * @param ...
 *   Arguments to the function.
 * @return
 *   The RPC status which is updated once a response arrives.
 * @note
 *   The function must be previously registered with tasvir_rpc_register.
 */
tasvir_rpc_status *tasvir_rpc(tasvir_area_desc *d, tasvir_fnptr fnptr, ...);

/**
 * @brief
 *   Blocking RPC call with timeout.
 *
 * @param timeout_us
 *   Timeout in microseconds.
 * @param retval
 *   Pointer to space to store return value at.
 * @param d
 *   The area this call must be executed on.
 * @param fnptr
 *   The function to invoke.
 * @param ...
 *   Arguments to the function.
 * @return
 *   True if the RPC was successful, false otherwise.
 * @note
 *   The function must be previously registered with tasvir_rpc_register.
 */
bool tasvir_rpc_wait(uint64_t timeout_us, void **retval, tasvir_area_desc *d, tasvir_fnptr fnptr, ...);

/**
 * @brief
 *   Register a function for proper invocation by the RPC subsystem.
 *
 * @param fni
 *   The function information necessary
 * @return
 *   True if an internal synchronization took place, false otherwise.
 * @note
 *   Call this function frequently (microsecond time scale) outside your critical sections.
 */
int tasvir_rpc_register(tasvir_fn_info *fni);

/**
 * @brief Invokes the Tasvir service routine.
 *
 * Handles pending RPC requests and invokes a synchronization routine if one is scheduled by the daemon
 * (i.e., enough time has elapsed since last synchronization).
 *
 * @return
 *   True if an internal synchronization took place, false otherwise.
 * @note
 *   You should call this function frequently (microsecond time scale).
 */
bool tasvir_service() __attribute__((hot));

/**
 * @brief
 *   Invokes the Tasvir service routine, requests daemon to schedule an internal synchronization immediately,
 *   and waits for it to happen for at most timeout_us microseconds.
 *
 * @return
 *   True if an internal synchronization took place, false otherwise.
 * @note
 *   Same as tasvir_service() except that it also forces an out-of-turn internal synchronization.
 * @note
 *   You may call this to make a write immediately visible on the local node. This is rarely needed.
 */
bool tasvir_service_wait(uint64_t timeout_us) __attribute__((hot));

/**
 * @brief
 *   Allocates a Tasvir area.
 *
 * @param d
 *   The specification of the area to be created.
 * @return
 *   The created area descriptor or NULL in case of failure.
 */
tasvir_area_desc *tasvir_new(tasvir_area_desc d);

/**
 * @brief
 *   Attaches to an area under pd by name on behalf of the given node.
 *
 * @param pd
 *   The parent area of the area to attach to.
 * @param name
 *   The name of the area to attach to.
 * @param node
 *   The node that is attaching to this area -- you may pass NULL for current node.
 * @param writer
 *   Set to false to attach to the local reader version of the area,
 *   and true to attach to the local writer copy of the area.
 * @return
 *   The area descriptor or NULL in case of failure (e.g., area not found).
 * @note
 *   Set writer to true iff you know what you are doing.
 */
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer);

/**
 * @brief
 *   Continuously tries to attach to an area until successful or a timeout occurs.
 *
 * @param pd
 *   The parent area of the area to attach to.
 * @param name
 *   The name of the area to attach to.
 * @param node
 *   The node that is attaching to this area -- you may pass NULL for current node.
 * @param writer
 *   Set to false to attach to the local reader version of the area,
 *   and true to attach to the local writer copy of the area.
 * @param timeout_us
 *   The timeout in microseconds.
 * @return
 *   The area descriptor or NULL in case of failure (e.g., area not found).
 * @note
 *   Mainly used for waiting for an area to be created by another thread.
 * @note
 *   Set writer to true iff you know what you are doing.
 */
tasvir_area_desc *tasvir_attach_wait(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer,
                                     uint64_t timeout_us);

/**
 * @brief
 *   Detach from the area.
 *
 * @param d
 *   The area to detach from.
 * @return
 *   0 on success, -1 otherwise.
 * @bug
 *   Not implemented yet.
 */
int tasvir_detach(tasvir_area_desc *d);

/**
 * @brief
 *   Delete the area.
 *
 * @param d
 *   The area to delete.
 * @return
 *   0 on success, -1 otherwise.
 * @bug
 *   Not implemented yet.
 */
int tasvir_delete(tasvir_area_desc *d);

/**
 * @brief
 *   Update the owner of the area.
 *
 * @param d
 *   The area to delete.
 * @return
 *   True if successful, false otherwise.
 * @bug
 *   Not implemented yet.
 */
bool tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner);

/**
 * @brief
 *   Get a pointer to the usable memory of an area.
 *
 * The usable memory of an area is right past the area header.
 * This function masks that implementation detail.
 *
 * @param d
 *   The area descriptor.
 * @return
 *   Pointer to the user memory.
 */
static inline void *tasvir_data(tasvir_area_desc *d) { return d->h + 1; }

/**
 *
 */
static inline tasvir_log_t *__attribute__((hot)) tasvir_data2log(const void *data) {
    return (tasvir_log_t *)TASVIR_ADDR_LOG + _pext_u64((uintptr_t)data, TASVIR_BITMASK_LOG_UNIT);
}

static inline uint64_t __attribute__((hot)) tasvir_data2log_bit_offset(const void *data) {
    return _pext_u64((uintptr_t)data, ((1UL << TASVIR_SHIFT_UNIT) - 1) & (~0UL << TASVIR_SHIFT_BIT));
}

/**
 *
 */
static inline void *__attribute__((hot)) tasvir_data2shadow(void *data) {
    return (uint8_t *)data + TASVIR_OFFSET_SHADOW;
}

/**
 * @brief
 *   Get a data pointer corresponding to a given log pointer.
 *
 * @param log
 *   A pointer to the log datum.
 * @return
 *   A pointer to the beginning of the correspondig data region.
 */
static inline void *__attribute__((hot)) tasvir_log2data(const void *log) {
    return (uint8_t *)((uintptr_t)log << TASVIR_SHIFT_BYTE) +
           (TASVIR_ADDR_DATA - (TASVIR_ADDR_LOG << TASVIR_SHIFT_BYTE));
}

/**
 *
 */
static inline void __attribute__((hot)) tasvir_log_write(const void *data, size_t len) {
    const void *data_end = (const uint8_t *)data + len;
    tasvir_log_t *log_start, *log_end;
    uint64_t idx_start, idx_end;
    uint64_t mask_first, mask_last;

    // idx_start = _pext_u64((uintptr_t)data, TASVIR_BITMASK_LOG_BIT);
    // idx_end = _pext_u64((uintptr_t)data_end, TASVIR_BITMASK_LOG_BIT);
    // log_start = (tasvir_log_t *)TASVIR_ADDR_LOG + (idx_start >> (TASVIR_SHIFT_UNIT - TASVIR_SHIFT_BIT));
    // log_end = (tasvir_log_t *)TASVIR_ADDR_LOG + (idx_end >> (TASVIR_SHIFT_UNIT - TASVIR_SHIFT_BIT));
    // idx_start &= TASVIR_LOG_UNIT_BITS - 1;
    // idx_end &= TASVIR_LOG_UNIT_BITS - 1;

    log_start = tasvir_data2log(data);
    log_end = tasvir_data2log(data_end);
    idx_start = tasvir_data2log_bit_offset(data);
    idx_end = tasvir_data2log_bit_offset(data_end);

    mask_first = ~0UL >> idx_start;
    mask_last = (1L << 63) >> idx_end;

    /*
       fprintf(stderr, "%14d %-22.22s %p-%p (%luB) log:%p-%p bit:%lu-%lu\n", 0, "tasvir_log_write", data, data_end, len,
       (void *)log_start, (void *)log_end, idx_start, idx_end);
    */

    if (log_start == log_end) {
        *log_start |= mask_first & mask_last;
    } else {
        *log_start |= mask_first;
        *log_end |= mask_last;
        while (log_start < log_end) {
            log_start++;
            *log_start = ~0UL;
        }
    }
}

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
