#ifdef TASVIR_DAEMON
#include "tasvir.h"

static void tasvir_msg_mem_generate(tasvir_area_desc *d, void *addr, size_t len, bool last, bool is_rw) {
    tasvir_msg_mem *m[TASVIR_PKT_BURST];
    size_t i = 0;

    while (rte_mempool_get_bulk(ttld.ndata->mp, (void **)m, TASVIR_PKT_BURST)) {
        LOG_DBG("rte_mempool_get_bulk failed");
        tasvir_service_port_tx();
    }

    while (len > 0) {
        m[i]->h.dst_tid = ttld.ndata->update_tid;
        m[i]->h.src_tid = ttld.thread->tid;
        m[i]->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
        m[i]->h.type = TASVIR_MSG_TYPE_MEM;
        m[i]->h.time_us = ttld.ndata->time_us;
        m[i]->d = d;
        m[i]->addr = addr;
        m[i]->len = MIN(TASVIR_CACHELINE_BYTES * TASVIR_NR_CACHELINES_PER_MSG, len);
        m[i]->h.mbuf.pkt_len = m[i]->h.mbuf.data_len =
            m[i]->len + offsetof(tasvir_msg_mem, line) - offsetof(tasvir_msg, eh);
        tasvir_mov_blocks_stream(m[i]->line, is_rw ? tasvir_data2shadow(addr) : addr, m[i]->len);

        addr = (uint8_t *)addr + m[i]->len;
        len -= m[i]->len;
        m[i]->last = len == 0 ? last : false;
        tasvir_populate_msg_nethdr((tasvir_msg *)m[i]);

        if (++i >= TASVIR_PKT_BURST) {
            while (rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)m, i, NULL) != i)
                tasvir_service_port_tx();

            while (rte_mempool_get_bulk(ttld.ndata->mp, (void **)m, TASVIR_PKT_BURST)) {
                LOG_DBG("rte_mempool_get_bulk failed");
                tasvir_service_port_tx();
            }
            i = 0;
        }
    }

    while (i > 0 && rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)m, i, NULL) != i)
        tasvir_service_port_tx();
    rte_mempool_put_bulk(ttld.ndata->mp, (void **)&m[i], TASVIR_PKT_BURST - i);
}

/* TODO: could use AVX */
static void tasvir_rotate_logs(tasvir_area_desc *d) {
    if (!d->active)
        return;

    /* always rotate the first one (assumption: rotate called right after an external sync)
     * rotate the second one after five seconds
     * rotate the third one after 15 seconds
     */
    uint64_t delta_us[TASVIR_NR_AREA_LOGS - 1] = {0, 5 * S2US, 15 * S2US};
    for (int i = TASVIR_NR_AREA_LOGS - 2; i >= 0; i--) {
        tasvir_area_log *log = &d->h->diff_log[i];
        tasvir_area_log *log_next = &d->h->diff_log[i + 1];
        tasvir_area_log *log2 = tasvir_data2shadow(log);
        tasvir_area_log *log2_next = tasvir_data2shadow(log_next);

        if (log->version_end > log->version_start && ttld.ndata->time_us - log->start_us > delta_us[i]) {
            tasvir_log_t *ptr = log->data;
            tasvir_log_t *ptr_next = log_next->data;
            tasvir_log_t *ptr_last = log_next->data;
            for (; ptr < ptr_last; ptr++, ptr_next++) {
                if (*ptr) {
                    *ptr_next |= *ptr;
                    *ptr = 0;
                }
            }
            LOG_DBG("%s rotating %d(v%lu-%lu,t%lu-%lu)->%d(v%lu-%lu,t%lu-%lu)", d->name, i, log->version_start,
                    log->version_end, log->start_us, log->end_us, i + 1, log_next->version_start, log_next->version_end,
                    log_next->start_us, log_next->end_us);
            log->version_start = log_next->version_end = log2->version_start = log2_next->version_end =
                log->version_end;
            log->start_us = log_next->end_us = log2->start_us = log2_next->end_us = log->end_us;
        }
    }
}

size_t tasvir_sync_external_area(tasvir_area_desc *d, bool init) {
    if (!d || !d->owner)
        return 0;

    if (d->sync_ext_us < ttld.ndata->sync_ext_us) {
        ttld.ndata->sync_ext_us = d->sync_ext_us;
        LOG_INFO("updating external sync interval to %luus", ttld.ndata->sync_ext_us);
    }

    if (!tasvir_area_is_local(d) || d->h->diff_log[0].version_end == 0)
        return 0;

    int i;
#ifdef TASVIR_DAEMON
    if (!d->pd && ttld.is_root) {
        tasvir_msg_mem_generate(NULL, d, TASVIR_ALIGNX(sizeof(tasvir_area_desc), TASVIR_CACHELINE_BYTES), true, true);
    }
#endif

    size_t nr_bits0 = 0;
    size_t nr_bits1 = 0;
    size_t nr_bits1_seen = 0;
    size_t nr_bits_seen = 0;
    size_t nr_bits_total = d->offset_log_end >> TASVIR_SHIFT_BIT;
    uint8_t nr_bits_same;
    uint8_t nr_bits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nr_bits_total);

    uint8_t *src = (uint8_t *)d->h;
    int pivot = 0;
    tasvir_log_t *log[TASVIR_NR_AREA_LOGS];
    tasvir_log_t log_val = 0;

    for (pivot = 0; pivot < TASVIR_NR_AREA_LOGS; pivot++) {
        if (!init && ttld.ndata->last_sync_ext_end > d->h->diff_log[pivot].end_us) {
            break;
        }
        log[pivot] = d->h->diff_log[pivot].data;
        log_val |= *log[pivot];
    }

    if (pivot == 0)
        return 0;

    bool is_rw = tasvir_area_is_mapped_rw(d);
    while (nr_bits_total > nr_bits_seen) {
        nr_bits_same = _lzcnt_u64(log_val);
        if (nr_bits_same > 0) {
            nr_bits_same = MIN(nr_bits_unit_left, nr_bits_same);
            nr_bits_seen += nr_bits_same;
            nr_bits0 += nr_bits_same;
            nr_bits_unit_left -= nr_bits_same;
            log_val <<= nr_bits_same;
        }

        if (nr_bits_unit_left > 0) {
            if (nr_bits0 > 0) {
                size_t tmp = (nr_bits0 + nr_bits1) << TASVIR_SHIFT_BIT;
                /* copy over for a previous batch of 1s */
                if (nr_bits1 > 0)
                    tasvir_msg_mem_generate(d, src, nr_bits1 << TASVIR_SHIFT_BIT, false, is_rw);
                src += tmp;
                nr_bits0 = nr_bits1 = 0;
            }

            nr_bits_same = _lzcnt_u64(~log_val);
            nr_bits_same = MIN(nr_bits_unit_left, nr_bits_same);
            nr_bits_seen += nr_bits_same;
            nr_bits1 += nr_bits_same;
            nr_bits1_seen += nr_bits_same;
            nr_bits_unit_left -= nr_bits_same;
            log_val = (log_val << (nr_bits_same - 1)) << 1;
        }

        if (nr_bits_unit_left == 0) {
            nr_bits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nr_bits_total - nr_bits_seen);
            log_val = 0;
            for (i = 0; i < pivot; i++) {
                log[i]++;
                log_val |= *log[i];
            }
        }
    }

    if (nr_bits1 > 0) {
        tasvir_msg_mem_generate(d, src, nr_bits1 << TASVIR_SHIFT_BIT, true, is_rw);
        tasvir_rotate_logs(d);
    } else if (nr_bits1_seen > 0) {
        tasvir_msg_mem_generate(d, NULL, 0, true, is_rw);
    }

    return nr_bits1_seen << TASVIR_SHIFT_BIT;
}

static size_t tasvir_sync_external_area_noinit(tasvir_area_desc *d) { return tasvir_sync_external_area(d, false); }

/* FIXME: no error handling/reporting */
int tasvir_sync_external() {
    return 0;
    ttld.ndata->last_sync_ext_start = ttld.ndata->time_us;
    size_t retval = tasvir_walk_areas(ttld.root_desc, &tasvir_sync_external_area_noinit);
    ttld.ndata->time_us = tasvir_gettime_us();
    ttld.ndata->last_sync_ext_end = ttld.ndata->time_us;
    return retval > 0 ? 0 : -1;
}
#endif
