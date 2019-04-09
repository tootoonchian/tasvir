#include <stdarg.h>
#include "tasvir.h"

static void tasvir_service_msg_rpc_request(tasvir_msg_rpc *m) {
    /* FIXME: badly insecure */
    tasvir_fn_desc *fnd = &ttld.fn_descs[m->fid];
    assert(fnd);

    /* execute the function */
    fnd->fnptr_rpc(m->data, fnd->arg_offsets);

    if (fnd->flags & TASVIR_FN_NOACK) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return;
    }

    /* convert the message into a response */
    m->h.dst_tid = m->h.src_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->nodecast_tid;
    m->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
    if (m->d->h && m->h.version == m->d->h->version) {
        LOG_ERR("rpc src and dst at the same version (area=%s v=%lu)", m->d->name, m->h.version);
        abort();
    }
    /* receiver compares msg version with the area version to ensure updates are seen */
    m->h.version = m->d->h ? m->d->h->version : 0;
    if (tasvir_service_msg((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0) {
        LOG_DBG("failed to send a response");
    }
}

static void tasvir_service_msg_rpc_response(tasvir_msg_rpc *m) {
    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    rs->status = TASVIR_RPC_STATUS_DONE;
    if (rs->do_free)
        rte_mempool_put(ttld.ndata->mp, (void *)m);
    else
        rs->response = m;
}

static inline void tasvir_service_msg_mem(tasvir_msg_mem *m) {
    /* TODO: log_write and sync */
    if (m->addr) {
        tasvir_log(m->addr, m->len);
        tasvir_stream_vec_rep(tasvir_data2shadow(m->addr), m->line, m->len);

        /* write to both versions during boot of a non-root daemon because no sync happens */
        if (unlikely(!ttld.thread ||
                     ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX].state == TASVIR_THREAD_STATE_BOOTING)) {
            tasvir_stream_vec_rep(m->addr, m->line, m->len);
        }
    }

    if (m->d && tasvir_area_is_active(m->d)) {
        // FIXME: assumes no reordering
        tasvir_area_header *h = tasvir_data2shadow(m->d->h);
        if (m->last) {
            h->flags_ &= ~TASVIR_AREA_CACHE_NETUPDATE;
        } else {
            h->flags_ |= TASVIR_AREA_CACHE_NETUPDATE;
        }
    }

    rte_mempool_put(ttld.ndata->mp, (void *)m);
}

/* FIXME: not robust */
int tasvir_service_msg(tasvir_msg *m, tasvir_msg_src src) {
    if (!m) {
        LOG_ERR("how can an empty message get here?")
        abort();
    }
    bool is_src_me = src == TASVIR_MSG_SRC_ME;
    bool is_dst_local =
        src == TASVIR_MSG_SRC_NET2US || memcmp(&m->dst_tid.nid, &ttld.ndata->nodecast_tid.nid, sizeof(tasvir_nid)) == 0;
    bool is_dst_me = src == TASVIR_MSG_SRC_NET2ROOT ||
                     (!is_src_me && is_dst_local && (!ttld.thread || m->dst_tid.idx == ttld.thread->tid.idx));

#ifdef TASVIR_DEBUG
    char msg_str[256];
    tasvir_msg2str(m, is_src_me, is_dst_me, msg_str, sizeof(msg_str));
    LOG_DBG("%s", msg_str);
#endif
    if (!is_dst_me) { /* no-op when message is ours */
        struct rte_ring *r;
#ifdef TASVIR_DAEMON
        if (is_dst_local) {
            r = ttld.ndata->tdata[m->dst_tid.idx == (uint16_t)-1 ? 0 : m->dst_tid.idx].ring_rx;
        } else {
            tasvir_populate_msg_nethdr(m);
            r = ttld.ndata->ring_ext_tx;
        }
#else
        r = ttld.ndata->tdata[ttld.thread ? ttld.thread->tid.idx : TASVIR_THREAD_DAEMON_IDX].ring_tx;
#endif

        if (r && rte_ring_sp_enqueue(r, m) != 0) {
            LOG_DBG("rte_ring_sp_enqueue to ring %p failed", (void *)r);
            rte_mempool_put(ttld.ndata->mp, (void *)m);
            return -1;
        }
        return 0;
    }
    /* end message routing */

    if (m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_service_msg_rpc_request((tasvir_msg_rpc *)m);
    } else if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        tasvir_service_msg_rpc_response((tasvir_msg_rpc *)m);
    } else {
        LOG_DBG("received an unrecognized message type %d", m->type);
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        abort();
        return -1;
    }
    return 0;
}

#ifdef TASVIR_DAEMON
void tasvir_service_port_tx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int count, i, retval;
    bool tx_fail = false;

    while (!rte_ring_empty(ttld.ndata->ring_ext_tx) && !tx_fail) {
        /* every message on ring_ext_tx must have already populated nethdr */
        count = rte_ring_sc_dequeue_burst(ttld.ndata->ring_ext_tx, (void **)m, TASVIR_PKT_BURST, NULL);

        i = 0;
        do {
            retval = rte_eth_tx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)&m[i], count - i);
            i += retval;
        } while (retval > 0 && i < count);

        if (i < count) {
            tx_fail = true;
            /* FIXME: reorders */
            if (rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)&m[i], count - i, NULL) == 0)
                abort();
            break;
        }
    }
}

static inline void tasvir_service_port_rx() {
    tasvir_msg *m[TASVIR_PKT_BURST];
    unsigned int retval, i;

    while ((retval = rte_eth_rx_burst(ttld.ndata->port_id, 0, (struct rte_mbuf **)m, TASVIR_PKT_BURST)) > 0) {
        for (i = 0; i < retval; i++) {
            if (m[i]->eh.ether_type == rte_cpu_to_be_16(TASVIR_ETH_PROTO)) {
                ttld.ndata->stats_cur.rx_bytes += m[i]->mbuf.pkt_len;
                ttld.ndata->stats_cur.rx_pkts++;

                if (is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->mac_addr)) {
                    tasvir_service_msg(m[i], TASVIR_MSG_SRC_NET2US);
                } else if (is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->update_tid.nid.mac_addr)) {
                    tasvir_service_msg_mem((tasvir_msg_mem *)m[i]);
                } else if (ttld.is_root &&
                           is_same_ether_addr(&m[i]->eh.d_addr, &ttld.ndata->rootcast_tid.nid.mac_addr)) {
                    tasvir_service_msg(m[i], TASVIR_MSG_SRC_NET2ROOT);
                } else {
                    rte_mempool_put(ttld.ndata->mp, (void *)m[i]);
                }
            } else {
                rte_mempool_put(ttld.ndata->mp, (void *)m[i]);
            }
        }
    }
}
#endif

static inline void tasvir_service_ring(struct rte_ring *ring) {
    tasvir_msg *m[TASVIR_RING_SIZE];
    unsigned count;

    while (unlikely((count = rte_ring_sc_dequeue_burst(ring, (void **)m, TASVIR_RING_SIZE, NULL)) > 0)) {
        for (unsigned i = 0; i < count; i++)
            tasvir_service_msg(m[i], TASVIR_MSG_SRC_LOCAL);
    }
}

static void tasvir_service_io() {
#ifdef TASVIR_DAEMON
    /* rings */
    if (ttld.node) {
        for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++)
            if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING ||
                ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_BOOTING) {
                tasvir_service_ring(ttld.ndata->tdata[tid].ring_tx);
            }
    }

    /* physical port */
    tasvir_service_port_rx();
    tasvir_service_port_tx();
#else
    tasvir_service_ring(ttld.tdata->ring_rx);
#endif
}

int tasvir_service() {
    /* upadte check-in time */
    ttld.tdata->time_us = tasvir_gettime_us();  // FIXME: assuming invariant tsc

    /* service internal rings and NIC ports */
    tasvir_service_io();

#ifdef TASVIR_DAEMON
    /* conditionally update time to reduce coherency traffic (TODO: granularity) */
    if (ttld.ndata->time_us != ttld.tdata->time_us) {
        ttld.ndata->time_us = ttld.tdata->time_us;
    }

    if (ttld.tdata->state != TASVIR_THREAD_STATE_RUNNING) {
        return -1;
    }

    if (ttld.ndata->stat_reset_req) {
        memset(&ttld.ndata->stats, 0, sizeof(tasvir_stats));
        memset(&ttld.ndata->stats_cur, 0, sizeof(tasvir_stats));
        ttld.ndata->last_stat = ttld.ndata->time_us;
        ttld.ndata->last_sync_int_start = ttld.ndata->time_us;
        ttld.ndata->last_sync_ext_start = ttld.ndata->time_us;
        ttld.ndata->last_sync_int_end = ttld.ndata->time_us;
        ttld.ndata->last_sync_ext_end = ttld.ndata->time_us;
        ttld.ndata->stat_reset_req = 0;
    }

    if (ttld.ndata->time_us - ttld.ndata->last_sync_ext_end >= ttld.ndata->sync_ext_us) {
        tasvir_sync_external();
    }

    if ((ttld.ndata->sync_req || ttld.ndata->time_us - ttld.ndata->last_sync_int_end >= ttld.ndata->sync_int_us)) {
        tasvir_sched_sync_internal();
    }

    if (ttld.ndata->stat_update_req || (ttld.ndata->time_us - ttld.ndata->last_stat >= TASVIR_STAT_US)) {
        tasvir_stats_update();
        ttld.ndata->stat_update_req = 0;
    }
#endif

    if (ttld.thread && ttld.tdata->state == TASVIR_THREAD_STATE_RUNNING && ttld.tdata->next_sync_seq != ttld.tdata->prev_sync_seq) {
        return tasvir_sync_internal();
    }

    return -1;
}

int tasvir_service_wait(uint64_t timeout_us) {
    int rc = -1;
    uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(timeout_us);
    while (__rdtsc() < end_tsc && (rc = tasvir_service()) != 0) {
        // _mm_pause();
        ttld.ndata->sync_req = true;
    }
    return rc;
}
