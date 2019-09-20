/**
 * @file
 *   defs.h
 * @brief
 *   Tasvir Definitions.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_DEFS_H_
#define TASVIR_DEFS_H_
#pragma once

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define TASVIR_STATIC_ASSERT static_assert
#else
#define TASVIR_STATIC_ASSERT _Static_assert
#endif

#define TASVIR_BARRIER_ENTER_US (50)     /**< Time (microseconds) to wait in the sync barrier */
#define TASVIR_STAT_US (1 * 1000 * 1000) /**< Time (microseconds) between updating and printing average statistics */
#define TASVIR_SYNC_INTERNAL_US (100 * 1000)  /**< Time (microseconds) between internal synchronization intervals */
#define TASVIR_SYNC_EXTERNAL_US (250 * 1000)  /**< Time (microseconds) between external synchronization intervals */
#define TASVIR_HEARTBEAT_US (1 * 1000 * 1000) /**< Time (microseconds) after which a node may be announced dead */

#define TASVIR_ETH_PROTO (0x88b6)                     /**< Ethernet protocol number to distinguish Tasvir traffic */
#define TASVIR_MBUF_POOL_SIZE (size_t)((2 << 17) - 1) /**< Size of the DPDK packet mbuf pool */
#define TASVIR_MBUF_CORE_CACHE_SIZE (size_t)(512)     /**< Size of the per-lcore mbuf cache size */
#define TASVIR_PKT_BURST (32)                         /**< Packet burst size to use for I/O */
#define TASVIR_RING_SIZE (256)                        /**< Maximum size of ring for internal I/O (bytes) */
#define TASVIR_RING_EXT_SIZE (4096)                   /**< Maximum size of ring for external I/O (bytes) */

#define TASVIR_NR_AREAS (1024)            /**< Maximum number of areas */
#define TASVIR_NR_AREA_LOGS (4)           /**< Number of internal logs (time intervals) kept per area */
#define TASVIR_NR_CACHELINES_PER_MSG (21) /**< Number of cachelines that fit in a single Tasvir message */
#define TASVIR_NR_FN (4096)               /**< Maximum number of RPC functions */
#define TASVIR_NR_RPC_ARGS (8)            /**< Maximum number of RPC function arguments */
#define TASVIR_NR_RPC_MSG (256 * 1024)    /**< Maximum number of outstanding RPC messages */
#define TASVIR_NR_NODES (64)              /**< Maximum number of nodes in Tasvir */
#define TASVIR_NR_SOCKETS (2)             /**< Maximum number of CPU sockets per node */
#define TASVIR_NR_SYNC_JOBS (2048)        /**< Maximum number of internal sync jobs */
#define TASVIR_NR_THREADS_LOCAL (64)      /**< Maximum number of local threads */
#define TASVIR_STRLEN_MAX (32)            /**< Maximum size of strings (bytes) */
#define TASVIR_THREAD_DAEMON_IDX (0)      /**< Local thread index for the daemon thread */

#define __TASVIR_LOG2(x) (31 - __builtin_clz(x | 1)) /**< Compile-time log2 for numbers that are power of two */

#define TASVIR_CACHELINE_BYTES (64)                                    /**< Cache line size (bytes) */
#define TASVIR_LOG_GRANULARITY_BYTES (64)                              /**< Granularity of each log bit (bytes) */
#define TASVIR_LOG_UNIT_BITS (64)                                      /**< Number of bits in each log unit */
#define TASVIR_SHIFT_BIT (__TASVIR_LOG2(TASVIR_LOG_GRANULARITY_BYTES)) /**<  */
#define TASVIR_SHIFT_BYTE (TASVIR_SHIFT_BIT + __TASVIR_LOG2(CHAR_BIT)) /**<  */
#define TASVIR_SHIFT_UNIT (TASVIR_SHIFT_BYTE + __TASVIR_LOG2(TASVIR_LOG_UNIT_BITS / CHAR_BIT)) /**<  */

#define TASVIR_ALIGNMENT (uintptr_t)(8 * (1 << TASVIR_SHIFT_UNIT)) /**< The default area alignment unit for Tasvir */
#define TASVIR_ALIGNX(x, a) (((uintptr_t)(x) + a - 1) & ~(a - 1))  /**< Align address/size x per alignment a */
#define TASVIR_ALIGN(x) TASVIR_ALIGNX((x), TASVIR_ALIGNMENT)       /**< Align address/size x per TASVIR_ALIGNMENT */

#define TASVIR_SIZE_DATA ((size_t)TASVIR_ALIGN(1UL << 40))                            /**< Data region size (bytes) */
#define TASVIR_SIZE_LOG ((size_t)TASVIR_ALIGN(TASVIR_SIZE_DATA >> TASVIR_SHIFT_BYTE)) /**< Log region size (bytes) */
#define TASVIR_SIZE_LOCAL ((size_t)TASVIR_ALIGN(1UL << 30))                           /**< Local region size (bytes) */

#define TASVIR_ALIGN_DATA(x) TASVIR_ALIGNX(x, TASVIR_SIZE_DATA) /**< Align address/size x per data region size */

#define TASVIR_ADDR_BASE ((uintptr_t)TASVIR_ALIGN_DATA(TASVIR_SIZE_DATA))      /**< Tasvir base virtual address */
#define TASVIR_ADDR_DATA ((uintptr_t)(TASVIR_ADDR_BASE))                       /**< Data region base virtual address */
#define TASVIR_ADDR_LOG ((uintptr_t)(TASVIR_ADDR_DATA + 2 * TASVIR_SIZE_DATA)) /**< Log region base virtual address */
#define TASVIR_ADDR_LOCAL ((uintptr_t)(TASVIR_ADDR_LOG + TASVIR_SIZE_LOG))     /**< Local region base virtual address */
#define TASVIR_ADDR_END ((uintptr_t)(TASVIR_ADDR_LOCAL + TASVIR_SIZE_LOCAL))
#define TASVIR_ADDR_DATA_RO ((uintptr_t)TASVIR_ALIGN_DATA(TASVIR_ADDR_END))
#define TASVIR_ADDR_DATA_RW ((uintptr_t)(TASVIR_ADDR_DATA_RO + TASVIR_SIZE_DATA))
#define TASVIR_ADDR_DPDK \
    ((uintptr_t)(TASVIR_ADDR_DATA_RW + TASVIR_SIZE_DATA + 4 * (1UL << 30))) /**< DPDK base virtual address */

#define TASVIR_SIZE_MAP (TASVIR_ADDR_END - TASVIR_ADDR_BASE)

#define TASVIR_OFFSET_RO (TASVIR_ADDR_DATA_RO - TASVIR_ADDR_DATA)
#define TASVIR_OFFSET_RW (TASVIR_ADDR_DATA_RW - TASVIR_ADDR_DATA)
#define TASVIR_OFFSET_RO2RW (TASVIR_ADDR_DATA_RW - TASVIR_ADDR_DATA_RO)
#define TASVIR_OFFSET_LOG (TASVIR_ADDR_LOG - TASVIR_ADDR_DATA)

/* source: http://ptspts.blogspot.com/2013/11/how-to-apply-macro-to-all-arguments-of.html */
#define TASVIR_NUM_ARGS_H1(dummy, x6, x5, x4, x3, x2, x1, x0, ...) x0
#define TASVIR_NUM_ARGS(...) TASVIR_NUM_ARGS_H1(dummy, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define TASVIR_APPLY0(t, dummy)
#define TASVIR_APPLY1(t, a) t(a, 0)
#define TASVIR_APPLY2(t, a, b) t(a, 0), t(b, 1)
#define TASVIR_APPLY3(t, a, b, c) t(a, 0), t(b, 1), t(c, 2)
#define TASVIR_APPLY4(t, a, b, c, d) t(a, 0), t(b, 1), t(c, 2), t(d, 3)
#define TASVIR_APPLY5(t, a, b, c, d, e) t(a, 0), t(b, 1), t(c, 2), t(d, 3), t(e, 4)
#define TASVIR_APPLY6(t, a, b, c, d, e, f) t(a, 0), t(b, 1), t(c, 2), t(d, 3), t(e, 4), t(f, 5)
#define TASVIR_APPLY_ALL_H3(t, n, ...) TASVIR_APPLY##n(t, __VA_ARGS__)
#define TASVIR_APPLY_ALL_H2(t, n, ...) TASVIR_APPLY_ALL_H3(t, n, __VA_ARGS__)
#define TASVIR_APPLY_ALL(t, ...) TASVIR_APPLY_ALL_H2(t, TASVIR_NUM_ARGS(__VA_ARGS__), __VA_ARGS__)
#define TASVIR_F_ARGVAL(t, i) *((t *)&((uint8_t *)v)[o[i]])
#define TASVIR_F_SIZEOF(t, i) sizeof(t)

#define TASVIR_RPCFN_DEFINE(fn, flags_val, ret_t, ...)                                       \
    static void fn##_RPCFN(void *v, ptrdiff_t *o) {                                          \
        *((ret_t *)&((uint8_t *)v)[0]) = fn(TASVIR_APPLY_ALL(TASVIR_F_ARGVAL, __VA_ARGS__)); \
    }                                                                                        \
    static void fn##_RPCFN_REGISTER() {                                                      \
        tasvir_rpc_fn_register(&(tasvir_fn_desc){                                            \
            .name = #fn,                                                                     \
            .fnptr_rpc = &fn##_RPCFN,                                                        \
            .fnptr = (tasvir_fnptr)&fn,                                                      \
            .flags = flags_val,                                                              \
            .argc = TASVIR_NUM_ARGS(__VA_ARGS__),                                            \
            .ret_len = sizeof(ret_t),                                                        \
            .arg_lens = {TASVIR_APPLY_ALL(TASVIR_F_SIZEOF, __VA_ARGS__)},                    \
        });                                                                                  \
    }
#define TASVIR_RPCFN_REGISTER(fn) fn##_RPCFN_REGISTER()

#define TASVIR_PUBLIC __attribute__((visibility("default")))

#endif /* TASVIR_DEFS_H_ */
