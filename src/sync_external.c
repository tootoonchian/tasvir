#ifdef TASVIR_DAEMON
#include "tasvir.h"

#ifdef TASVIR_DAEMON
void tasvir_handle_msg_mem(tasvir_msg_mem *m) {
    // FIXME: incoming only. not robust. assumes lossless in-order delivery
    // TODO: remove the outgoing code from msg_mem_generate and bring it here
    if (!m->h.d->h)
        goto cleanup;
    tasvir_area_header *h_rw = tasvir_data2rw(m->h.d->h);
    if (h_rw->flags_ & TASVIR_AREA_FLAG_EXT_ENQUEUE) {
        if (!rte_ring_sp_enqueue(ttld.ndata->ring_mem_pending, m))
            return;
        h_rw->flags_ &= ~TASVIR_AREA_FLAG_EXT_ENQUEUE;
        h_rw->flags_ |= TASVIR_AREA_FLAG_EXT_IGNORE;
        goto cleanup;
    }
    if (h_rw->last_sync_ext_v_ != m->h.version) {
        h_rw->last_sync_ext_v_ = m->h.version;
        h_rw->last_sync_ext_bytes_ = 0;
        h_rw->flags_ &= ~TASVIR_AREA_FLAG_EXT_IGNORE;
        h_rw->flags_ |= TASVIR_AREA_FLAG_EXT_PENDING;
    }
    if (h_rw->flags_ & TASVIR_AREA_FLAG_EXT_IGNORE || !(h_rw->flags_ & TASVIR_AREA_FLAG_EXT_PENDING)) {
        goto cleanup;
    }
    if (h_rw->last_sync_ext_bytes_ != m->prev_bytes) {
        // LOG_ERR("%s missed pkts prev_bytes=%lu vs %lu", m->h.d->name, h_rw->last_sync_ext_bytes_, m->prev_bytes);
        h_rw->flags_ &= ~TASVIR_AREA_FLAG_EXT_PENDING;
        h_rw->flags_ |= TASVIR_AREA_FLAG_EXT_IGNORE;
    }
    if (m->addr) {
        tasvir_log(m->addr, m->len);
        tasvir_stream_vec_rep(tasvir_data2rw(m->addr), m->line, m->len);
        h_rw->last_sync_ext_bytes_ += m->len;
        /* write to both versions during boot of a non-root daemon because no sync happens */
        if (tasvir_is_booting())
            tasvir_stream_vec_rep(tasvir_data2ro(m->addr), m->line, m->len);
    }
    if (m->last) {
        h_rw->flags_ &= ~TASVIR_AREA_FLAG_EXT_PENDING;
        h_rw->flags_ |= TASVIR_AREA_FLAG_ACTIVE;
        if (tasvir_is_booting()) {
            tasvir_area_header *h_ro = tasvir_data2ro(m->h.d->h);
            h_ro->flags_ |= TASVIR_AREA_FLAG_ACTIVE;
        } else if (ttld.ndata->time_us - ttld.ndata->last_sync_int_end > 0.5 * ttld.ndata->sync_int_us) {
            h_rw->flags_ |= TASVIR_AREA_FLAG_EXT_ENQUEUE;
        }
    }

#ifdef TASVIR_DEBUG_PRINT_MSG_MEM
    char msg_str[256];
    tasvir_msg_str((tasvir_msg *)m, false, true, msg_str, sizeof(msg_str));
    LOG_DBG("%s", msg_str);
#endif

cleanup:
    rte_mempool_put(ttld.ndata->mp, (void *)m);
}
#endif

/* TODO: could use AVX */
static void tasvir_rotate_logs(tasvir_area_desc *__restrict d) {
    /* (assumption: rotate called right after an external sync)
     * rotate the first one on every sync (done inline in tasvir_sync_parse_log)
     * rotate the second one after five seconds
     * rotate the third one after 15 seconds
     */
    const __m512i zero_v = _mm512_setzero_si512();

    uint64_t delta_us[TASVIR_NR_AREA_LOGS - 1] = {0, 5 * S2US, 21 * S2US};
    for (int i = TASVIR_NR_AREA_LOGS - 2; i > 0; i--) {
        tasvir_area_log_header *__restrict l1 = &d->h->diff_log[i];
        tasvir_area_log_header *__restrict l2 = &d->h->diff_log[i + 1];

        bool cond = l1->version_end > l1->version_start && ttld.ndata->time_us - l1->start_us > delta_us[i];
        if (cond) {
            __m512i *ptr = (__m512i *)l1->data;
            __m512i *ptr_next = (__m512i *)l2->data;
            __m512i *ptr_last = (__m512i *)l2->data;
            for (; ptr < ptr_last; ptr++, ptr_next++) {
                __m512i val = _mm512_load_si512(ptr);
                __mmask16 one_mask = _mm512_test_epi64_mask(val, val);
                if (one_mask) {
                    __m512i val_next = _mm512_load_si512(ptr_next);
                    _mm512_store_epi64((__m512i *)ptr_next, _mm512_or_epi64(val, val_next));
                    _mm512_store_epi64((__m512i *)ptr, zero_v);
                }
            }
#if 1  // TASVIR_DEBUG_PRINT_LOG_ROTATE
            LOG_DBG("%s rotating %d(v%lu-%lu,t%lu-%lu)->%d(v%lu-%lu,t%lu-%lu)", d->name, i, l1->version_start,
                    l1->version_end, l1->start_us, l1->end_us, i + 1, l2->version_start, l2->version_end, l2->start_us,
                    l2->end_us);
#endif
            l1->version_start = l2->version_end = l1->version_end;
            l1->start_us = l2->end_us = l1->end_us;
        }
    }
}

size_t tasvir_sync_external_area(tasvir_area_desc *d) {
    if (!d || !d->owner || !tasvir_area_is_local(d) || d->h->diff_log[0].version_end == 0)
        return 0;

    tasvir_area_header *h_ro = tasvir_data2ro(d->h);
    if (ttld.tdata->time_us - h_ro->last_sync_ext_us_ < d->sync_ext_us || h_ro->flags_ & TASVIR_AREA_FLAG_SLEEPING)
        return 0;

    h_ro->last_sync_ext_us_ = ttld.tdata->time_us;
    h_ro->last_sync_ext_bytes_ = 0;
    bool init = ttld.ndata->is_root && (d == ttld.root_desc || d == ttld.node_desc) && ttld.ndata->node_init_req;
    int pivot = init ? TASVIR_NR_AREA_LOGS - 1 : 0;
    uint64_t version_min = -1;
    for (size_t i = 0; i < d->h->nr_users; i++)
        if (d->h->users[i].node && *d->h->users[i].version < version_min)
            version_min = *d->h->users[i].version;
    for (; pivot < TASVIR_NR_AREA_LOGS && version_min < d->h->diff_log[pivot].version_end; pivot++)
        ;
    if (pivot == 0)
        return 0;
#ifdef TASVIR_DEBUG_PRINT_PIVOT
    LOG_ERR("%s v=%lu pivot=%d (%lu-%lu %lu-%lu %lu-%lu %lu-%lu)", d->name, version_min, pivot,
            d->h->diff_log[0].version_start, d->h->diff_log[0].version_end, d->h->diff_log[1].version_start,
            d->h->diff_log[1].version_end, d->h->diff_log[2].version_start, d->h->diff_log[2].version_end,
            d->h->diff_log[3].version_start, d->h->diff_log[3].version_end);
#endif

    size_t bytes_changed = tasvir_sync_parse_log(d, 0, d->len_logged, pivot);
    if (bytes_changed) {
        ttld.ndata->stats_cur.esync_changed_bytes += bytes_changed;
        tasvir_rotate_logs(d);
    }
    ttld.ndata->stats_cur.esync_processed_bytes += d->len_logged;

    return bytes_changed;
}

/* FIXME: no error handling/reporting */
int tasvir_sync_external() {
    ttld.ndata->last_sync_ext_start = ttld.ndata->time_us;
    /* update external sync frequency per that of subscribed areas */
    for (size_t i = 0; i < ttld.node->nr_areas; i++) {
        tasvir_area_desc *d = ttld.node->areas_d[i];
        if (d->sync_ext_us >= ttld.ndata->sync_ext_us)
            continue;
        uint64_t sync_ext_us = tasvir_area_is_local(d) ? d->sync_ext_us / 2 : d->sync_ext_us;
        ttld.ndata->sync_ext_us = sync_ext_us;
        LOG_INFO("updating external sync interval to %luus", ttld.ndata->sync_ext_us);
        if (!ttld.ndata->is_root)
            continue;
        tasvir_log(&ttld.root_desc->sync_ext_us, sizeof(ttld.root_desc->sync_ext_us));
        ttld.root_desc->sync_ext_us = sync_ext_us;
        for (size_t i = 0; i < ttld.node->nr_areas; i++) {
            tasvir_area_desc *nd = ttld.node->areas_d[i];
            if (nd->type == TASVIR_AREA_TYPE_NODE) {
                tasvir_log(&nd->sync_ext_us, sizeof(nd->sync_ext_us));
                nd->sync_ext_us = sync_ext_us;
            }
        }
    }

    size_t retval = tasvir_area_walk(ttld.root_desc, &tasvir_sync_external_area);
    ttld.ndata->node_init_req = false;
    ttld.ndata->time_us = tasvir_time_us();
    ttld.ndata->last_sync_ext_end = ttld.ndata->time_us;
    ttld.ndata->stats_cur.esync_cnt++;
    ttld.ndata->stats_cur.esync_us += ttld.ndata->last_sync_ext_end - ttld.ndata->last_sync_ext_start;

    return retval > 0 ? 0 : -1;
}
#endif
