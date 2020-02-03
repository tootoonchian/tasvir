#include <rte_ethdev.h>
#include <stdarg.h>

#include "tasvir.h"

#ifdef TASVIR_DAEMON
void tasvir_service_port_tx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int count, i, retval;
    bool tx_fail = false;
    struct rte_ring *__restrict r = ttld.ndata->ring_ext_tx;

    while (!rte_ring_empty(r) && !tx_fail) {
        /* every message on ring_ext_tx must have already populated nethdr */
        count = rte_ring_sc_dequeue_burst(r, (void **)m, TASVIR_PKT_BURST, NULL);
        i = 0;
        do {
            retval = rte_eth_tx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)&m[i], count - i);
            if (!retval)
                _mm_pause();
            i += retval;
        } while (i < count);
    }
}

static inline void tasvir_service_port_rx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int retval, i;

    while ((retval = rte_eth_rx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)m, TASVIR_PKT_BURST)) > 0) {
        for (i = 0; i < retval; i++) {
            bool valid = false;
            /* filter out and pass on Tasvir-typed messages */
            if (m[i]->eh.ether_type == rte_cpu_to_be_16(TASVIR_ETH_PROTO)) {
                ttld.ndata->stats_cur.rx_bytes += m[i]->mbuf.pkt_len;
                ttld.ndata->stats_cur.rx_pkts++;

                if (!memcmp(&m[i]->eh.ether_dhost, &ttld.ndata->memcast_tid.nid.mac_addr, ETH_ALEN)) {
                    valid = true;
                    tasvir_handle_msg_mem((tasvir_msg_mem *)m[i]);
                } else if (!memcmp(&m[i]->eh.ether_dhost, &ttld.ndata->mac_addr, ETH_ALEN) ||
                           !memcmp(&m[i]->eh.ether_dhost, &ttld.ndata->rpccast_tid.nid.mac_addr, ETH_ALEN)) {
                    valid = true;
                    tasvir_handle_msg_rpc(m[i], TASVIR_MSG_SRC_NET);
                }
            }
            if (!valid) {
                rte_mempool_put(ttld.ndata->mp, (void *)m[i]);
            }
        }
    }
}
#endif

static inline void tasvir_service_ring(struct rte_ring *ring, bool rpc) {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned count;

    while ((count = rte_ring_sc_dequeue_burst(ring, (void **)m, TASVIR_PKT_BURST, NULL)) > 0) {
        for (unsigned i = 0; i < count; i++)
            if (rpc)
                tasvir_handle_msg_rpc(m[i], TASVIR_MSG_SRC_LOCAL);
#ifdef TASVIR_DAEMON
            else
                tasvir_handle_msg_mem((tasvir_msg_mem *)m[i]);
#endif
    }
}


static void tasvir_service_io() {
#ifdef TASVIR_DAEMON
    /* local rings */
    if (ttld.node) {
        for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++)
            if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING ||
                ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_BOOTING)
                tasvir_service_ring(ttld.ndata->tdata[tid].ring_tx, true);
    }

    /* physical port */
    if (ttld.ndata->port_id != (uint16_t)-1 &&
        (!ttld.ndata->is_root || tasvir_is_running())) {  // no I/O during root's boot
        tasvir_service_port_rx();
        tasvir_service_port_tx();
    }
#else
    tasvir_service_ring(ttld.tdata->ring_rx, true);
#endif
}

void tasvir_service_nodes() {
    static uint64_t v_prev = 0;
    if (ttld.root_desc->h->version == v_prev)
        return;

    v_prev = ttld.root_desc->h->version;
    /* attach to new node areas */
    for (size_t i = 0; i < ttld.root_desc->h->nr_areas; i++)
        if (ttld.root_desc->h->child[i].type == TASVIR_AREA_TYPE_NODE)
            tasvir_attach_wait(100 * MS2US, ttld.root_desc->h->child[i].name);
}

int tasvir_service() {
    if (!ttld.tdata)
        return -1;

    /* upadte check-in time */
    ttld.tdata->time_us = tasvir_time_us();  // FIXME: assuming invariant tsc

    /* service internal rings and NIC ports */
    tasvir_service_io();

#ifdef TASVIR_DAEMON
    if (ttld.ndata->time_us != ttld.tdata->time_us) /* conditional update to reduce coherency traffic */
        ttld.ndata->time_us = ttld.tdata->time_us;
#endif

    if (!tasvir_is_running())
        return -1;

#ifdef TASVIR_DAEMON
    if (ttld.ndata->stat_reset_req)
        tasvir_stats_reset();

    tasvir_service_nodes();

    if (ttld.ndata->sync_req || ttld.ndata->time_us - ttld.ndata->last_sync_int_end >= ttld.ndata->sync_int_us)
        tasvir_sched_sync_internal();
#endif

    int retval = -1;
    if (ttld.tdata->next_sync_seq != ttld.tdata->prev_sync_seq) {
        retval = tasvir_sync_internal();
#ifdef TASVIR_DAEMON
        if (!retval) /* process pending memory updates */
            tasvir_service_ring(ttld.ndata->ring_mem_pending, false);
#endif
    }

#ifdef TASVIR_DAEMON
    if (ttld.ndata->port_id != (uint16_t)-1 &&
        ttld.ndata->time_us - ttld.ndata->last_sync_ext_end >= ttld.ndata->sync_ext_us)
        tasvir_sync_external();

    if (ttld.ndata->stat_update_req || (ttld.ndata->time_us - ttld.ndata->last_stat >= TASVIR_STAT_US))
        tasvir_stats_update();
#endif

    return retval;
}

int tasvir_service_wait(uint64_t timeout_us, bool sync_req) {
    int retval = -1;
    if (sync_req)
        ttld.ndata->sync_req = true;
    uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(timeout_us);
    while (__rdtsc() < end_tsc && (retval = tasvir_service()))
        _mm_pause();
    return retval;
}
