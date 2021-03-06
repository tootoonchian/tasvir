/**
 * @file
 *   tasvir.h
 * @brief
 *   Tasvir Types.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_TYPES_H_
#define TASVIR_TYPES_H_
#pragma once

#include <math.h>
#include <mmintrin.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uthash.h>

#include <tasvir/defs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long tasvir_arg_promo_t;
#if TASVIR_LOG_UNIT_BITS == 64
typedef uint64_t tasvir_log_t;
#else
#error TASVIR_LOG_UNIT_BIT other than 64 is not supported.
#endif
typedef uint8_t tasvir_cacheline[TASVIR_CACHELINE_BYTES];
typedef char tasvir_str[TASVIR_STRLEN_MAX];
typedef struct {
    tasvir_str str;
} tasvir_str_static;
typedef void (*tasvir_fnptr_rpc)(void *, ptrdiff_t *);
typedef void (*tasvir_fnptr)(void);
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

/**
 *
 */
typedef enum {
    TASVIR_RC_SUCCESS = 0,
    TASVIR_RC_BAD = 1,
    TASVIR_RC_LAST = 255,
} tasvir_ret_code;

/**
 *
 */
typedef enum {
    TASVIR_RPC_STATUS_INVALID = 0,
    TASVIR_RPC_STATUS_PENDING,
    TASVIR_RPC_STATUS_FAILED,
    TASVIR_RPC_STATUS_DONE
} tasvir_rpc_status_type;

typedef enum {
    TASVIR_FN_NOACK = 1,    /* function does not expect an ack; i.e., unreliable delivery */
    TASVIR_FN_NOMODIFY = 2, /* function does not modify the area; i.e., sender must check */
} tasvir_fn_flag;

typedef struct tasvir_msg_rpc tasvir_msg_rpc;

/**
 * Function descriptor used by RPC.
 */
typedef struct tasvir_fn_desc {
    tasvir_str name;
    tasvir_fnptr_rpc fnptr_rpc;
    tasvir_fnptr fnptr;
    uint32_t fid;
    uint8_t flags;
    uint8_t argc;
    int ret_len;
    size_t arg_lens[TASVIR_NR_RPC_ARGS];
    ptrdiff_t arg_offsets[TASVIR_NR_RPC_ARGS];
    UT_hash_handle h_fnptr;
} tasvir_fn_desc;

/**
 * Status of a pending RPC
 */
typedef struct tasvir_rpc_status {
    bool do_free;
    uint16_t id;
    tasvir_fn_desc *fnd;
    tasvir_rpc_status_type status;
    tasvir_msg_rpc *response;
} tasvir_rpc_status;


typedef struct tasvir_node tasvir_node;
typedef struct tasvir_thread tasvir_thread;

/**
 *
 */
typedef struct tasvir_area_desc {
    tasvir_area_desc *pd;  /* parent descriptor */
    tasvir_area_header *h; /* the header */
    tasvir_thread *owner;  /* current owner */
    size_t len;            /* area length including the metadata (header and log) */
    size_t len_logged;     /* area length for log processing */
    uint64_t sync_int_us;  /* internal synchronization interval in microseconds */
    uint64_t sync_ext_us;  /* external synchronization interval in microseconds */
    tasvir_area_type type; /* area type */
    union {
        tasvir_str name;
        tasvir_str_static name0;
    }; /* name of the area */
} tasvir_area_desc;

/**
 *
 */
typedef struct tasvir_area_log_header {
    uint64_t version_start;
    uint64_t version_end;
    uint64_t start_us;
    uint64_t end_us;
    tasvir_log_t *data;
} tasvir_area_log_header;

/**
 *
 */
typedef struct __attribute__((aligned(TASVIR_CACHELINE_BYTES))) tasvir_area_header {
    union {
#ifndef __cplusplus
        struct {
            uint64_t flags_;
            uint64_t last_sync_ext_bytes_;
            uint64_t last_sync_ext_us_;
            uint64_t last_sync_ext_v_;
            void *extent_hooks_;
            int arena_ind_;
        };
#endif
        uint8_t pad_[1 << TASVIR_SHIFT_BIT];
    }; /* guaranteed to be local, i.e., not synced */
    tasvir_area_desc *d;
    uint64_t version;
    uint64_t time_us;

    size_t len_dalloc;

    tasvir_area_log_header diff_log[TASVIR_NR_AREA_LOGS];

    size_t nr_users;
    struct {
        tasvir_node *node;
        uint64_t *version;
    } users[TASVIR_NR_NODES];

    size_t nr_areas;
    tasvir_area_desc child[1]; /* variable-length array (nr_areas) */
} tasvir_area_header;

/**
 *
 */
typedef struct tasvir_stats {
    uint64_t isync_success;
    uint64_t isync_failure;
    uint64_t isync_barrier_us;
    uint64_t isync_us; /* inclusive of isync_barrier_us */
    uint64_t isync_changed_bytes;
    uint64_t isync_processed_bytes;

    uint64_t esync_cnt;
    uint64_t esync_us;
    uint64_t esync_changed_bytes;
    uint64_t esync_processed_bytes;

    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_pkts;
    uint64_t tx_pkts;
} tasvir_stats;

#ifdef __cplusplus
}
#endif
#endif /* TASVIR_TYPES_H_ */
