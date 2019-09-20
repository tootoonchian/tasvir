/**
 * @file
 *   tasvir.h
 * @brief
 *   Tasvir API.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_TASVIR_H_
#define TASVIR_TASVIR_H_
#pragma once

#include <immintrin.h>
#include <math.h>
#include <mmintrin.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <tasvir/defs.h>
#include <tasvir/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SERVICE */
/**
 * @brief
 *   Initialize Tasvir.
 *
 * @return
 *   The root area descriptor.
 * @note
 *   Must be called very early in program execution and before any other interaction with Tasvir.
 * @note
 *   Each application thread that interacts with Tasvir-backed memory must call this function.
 */
TASVIR_PUBLIC __attribute__((noinline)) tasvir_area_desc *tasvir_init();

/**
 * @brief
 *   Invokes the Tasvir service routine.
 *   Handles pending RPC requests and invokes a synchronization routine if one is scheduled by the daemon
 *   (i.e., enough time has elapsed since last synchronization).
 *
 * @return
 *   0 if an internal synchronization took place, an error code (-1 for now) otherwise.
 * @note
 *   Call this function every few microseconds (more frequently than TASVIR_BARRIER_ENTER_US / 2)
 *   except when Tasvir areas are not in use (tasvir_activate(false)).
 */
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_service();

/**
 * @brief
 *   Invokes the Tasvir service routine, requests daemon to schedule an internal synchronization immediately,
 *   and waits for it to happen for at most timeout_us microseconds.
 *
 * @param timeout_us
 *   The timeout in microseconds.
 * @param sync_req
 *   Request daemon to schedule a synchronization if set.
 * @return
 *   0 if an internal synchronization took place, an error code (-1 for now) otherwise.
 * @note
 *   Same as tasvir_service() except that it requests and waits for an immediate internal synchronization.
 * @note
 *   You may call this to make a write immediately visible on the local node. This is rarely needed.
 */
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_service_wait(uint64_t timeout_us, bool sync_req);

/**
 * @brief
 *   Marks the current thread inactive; synchronization will proceed without this thread.
 *   A thread marked inactive must not interact with Tasvir-allocated areas.
 *   By default, threads are marked active and expected to check in frequqently
 *
 *   Mark a thread inactive before engaging in lengthy initialization or disk I/O.
 */
TASVIR_PUBLIC __attribute__((noinline)) void tasvir_activate(bool active);

/* AREA */
/**
 * @brief
 *   Marks the area inactive so that synchronization will skip processing it.
 *   This function must only invoked by the area owner.
 *   By default, areas are marked active and expected to check in frequqently
 *
 *   Mark an area inactive if engaging in lengthy modifications to the area which you want to appear
 *   atomically elsewhere. Of course, do not forget to reactivate it :-)
 */
TASVIR_PUBLIC __attribute__((noinline)) void tasvir_area_activate(tasvir_area_desc *d, bool active);

/**
 * @brief
 *   Allocates a Tasvir area.
 *
 * @param d
 *   The specification of the area to be created.
 * @return
 *   The created area descriptor or NULL in case of failure.
 */
TASVIR_PUBLIC __attribute__((noinline)) tasvir_area_desc *tasvir_new(tasvir_area_desc d);

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
TASVIR_PUBLIC __attribute__((noinline)) tasvir_area_desc *tasvir_attach(const char *name);

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
TASVIR_PUBLIC __attribute__((noinline)) tasvir_area_desc *tasvir_attach_wait(uint64_t timeout_us, const char *name);

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
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_detach(tasvir_area_desc *d);

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
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_delete(tasvir_area_desc *d);

/**
 * @brief
 *   Update the owner of the area.
 *
 * @param d
 *   The area to delete.
 * @return
 *   0 on success, an error code (-1 for now) otherwise.
 * @bug
 *   Not implemented yet.
 */
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner);

/**
 * @brief
 *   Get a pointer to the usable memory of an area.
 *
 * This region is currently right past the area header.
 * This function masks that implementation detail.
 *
 * @param d
 *   The area descriptor.
 * @return
 *   Pointer to the user memory.
 */
static inline void *tasvir_data(tasvir_area_desc *d) { return d->h + 1; }

/* LOG */
/**
 * @brief
 *   Log a change of \p len bytes to the address \p data.
 *
 * @param data
 *   Changed address.
 * @param len
 *   Change size in bytes.
 */
static inline void tasvir_log(const void *__restrict data, size_t len) {
    /* find the start and end bit offset in the log corresponding to the start and end address */
    size_t logbit_idx0 = _pext_u64((uintptr_t)data, (TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_BIT));
    size_t logbit_idx1 = _pext_u64((uintptr_t)data + len - 1, (TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_BIT));
    size_t logunit_idx0 = logbit_idx0 >> (TASVIR_SHIFT_UNIT - TASVIR_SHIFT_BIT);
    size_t logunit_idx1 = logbit_idx1 >> (TASVIR_SHIFT_UNIT - TASVIR_SHIFT_BIT);
    tasvir_log_t mask0 = ~(tasvir_log_t)0 >> (logbit_idx0 % TASVIR_LOG_UNIT_BITS);
    tasvir_log_t mask1 = (1L << 63) >> (logbit_idx1 % TASVIR_LOG_UNIT_BITS);
    size_t logdiff = logunit_idx1 - logunit_idx0;
    tasvir_log_t *__restrict log = (tasvir_log_t *)TASVIR_ADDR_LOG + logunit_idx0;

    if (!logdiff) {
        tasvir_log_t val_new = log[0] | (mask0 & mask1);
        if (log[0] != val_new)  // save coherency+write traffic in the common case
            log[0] = val_new;
    } else {
        size_t i;
        log[0] |= mask0;
        for (i = 1; i < logdiff; i++)
            log[i] = ~(tasvir_log_t)0;
        log[logdiff] |= mask1;
    }

#ifdef TASVIR_DEBUG_TRACKING
    fprintf(stderr, "%16d %-22.22s %p (%luB) log/offset:%p/%u\n", 0, "tasvir_log", data, len, (void *)log, logbit_idx);
#endif
}

/* RPC */
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
 *   The function must be previously registered with tasvir_rpc_fn_register.
 */
TASVIR_PUBLIC tasvir_rpc_status *tasvir_rpc(tasvir_area_desc *d, tasvir_fnptr fnptr, ...);

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
 *   0 on success, an error code (-1 for now) otherwise.
 * @note
 *   The function must be previously registered with tasvir_rpc_fn_register.
 */
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_rpc_wait(uint64_t timeout_us, void **retval, tasvir_area_desc *d,
                                                            tasvir_fnptr fnptr, ...);

/**
 * @brief
 *   Register a function for proper invocation by the RPC subsystem.
 *
 * @param fnd
 *   The function descriptor
 * @return
 *   True if an internal synchronization took place, false otherwise.
 * @note
 *   Call this function frequently (microsecond time scale) outside your critical sections.
 */
TASVIR_PUBLIC __attribute__((noinline)) int tasvir_rpc_fn_register(tasvir_fn_desc *fnd);


/* STATS */
/**
 * @brief
 *   Get a copy of internally collected synchronization statistics.
 *
 * @note
 *   Mainly used for benchmarking purposes.
 */
TASVIR_PUBLIC __attribute__((noinline)) tasvir_stats tasvir_stats_get(void);

/**
 * @brief
 *   Reset internally maintained statistics.
 *
 * @note
 *   Mainly used for benchmarking purposes.
 */
TASVIR_PUBLIC __attribute__((noinline)) void tasvir_stats_reset(void);

#ifdef __cplusplus
}
#endif
#endif /* TASVIR_TASVIR_H_ */
