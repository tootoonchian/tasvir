#include "tasvir.h"

#ifdef TASVIR_DAEMON
static void tasvir_msg_mem_generate(const tasvir_area_desc *__restrict d, void *addr, size_t len, bool last) {
    tasvir_msg_mem *m[TASVIR_PKT_BURST];
    while (rte_mempool_get_bulk(ttld.ndata->mp, (void **)m, TASVIR_PKT_BURST)) {
        LOG_DBG("rte_mempool_get_bulk failed.");
        tasvir_service_port_tx();
    }

    size_t i = 0;
    tasvir_area_header *h_ro = (tasvir_area_header *)tasvir_data2ro(d->h);
    uint64_t prev_bytes = h_ro->last_sync_ext_bytes_;
    uint64_t v = h_ro->version;
    while (len > 0) {
        m[i]->h.dst_tid = ttld.ndata->memcast_tid;
        m[i]->h.src_tid = ttld.thread->tid;
        m[i]->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
        m[i]->h.type = TASVIR_MSG_TYPE_MEM;
        m[i]->h.d = d;
        m[i]->h.version = v;
        m[i]->addr = addr;
        m[i]->len = MIN(TASVIR_CACHELINE_BYTES * TASVIR_NR_CACHELINES_PER_MSG, len);
        m[i]->prev_bytes = prev_bytes;
        m[i]->h.mbuf.pkt_len = m[i]->h.mbuf.data_len =
            m[i]->len + offsetof(tasvir_msg_mem, line) - offsetof(tasvir_msg, eh);
        tasvir_stream_vec_rep(m[i]->line, tasvir_data2ro(addr), m[i]->len);

        prev_bytes += m[i]->len;

        addr = (uint8_t *)addr + m[i]->len;
        len -= m[i]->len;
        m[i]->last = last && len == 0;
        tasvir_populate_msg_nethdr((tasvir_msg *)m[i]);

#ifdef TASVIR_DEBUG_PRINT_MSG_MEM
        char msg_str[256];
        tasvir_msg_str((tasvir_msg *)m[i], true, false, msg_str, sizeof(msg_str));
        LOG_DBG("%s", msg_str);
#endif
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
    h_ro->last_sync_ext_bytes_ = prev_bytes;

    while (i && rte_ring_sp_enqueue_bulk(ttld.ndata->ring_ext_tx, (void **)m, i, NULL) != i)
        tasvir_service_port_tx();
    rte_mempool_put_bulk(ttld.ndata->mp, (void **)&m[i], TASVIR_PKT_BURST - i);
}
#endif

size_t tasvir_sync_process_changes(UNUSED const tasvir_area_desc *d, bool reset_changed, UNUSED bool external) {
    tasvir_sync_list *__restrict l = &ttld.tdata->sync_list;
    for (int i = 0; i < l->cnt; i++) {
        size_t offset = l->l[i].offset_scaled << TASVIR_SHIFT_BIT;
        size_t len = l->l[i].len_scaled << TASVIR_SHIFT_BIT;
#ifdef TASVIR_DAEMON
        if (external) {
            uint8_t *src = (uint8_t *)TASVIR_ADDR_DATA + offset;
            tasvir_msg_mem_generate(d, src, len, reset_changed && i == l->cnt - 1);
        } else
#endif
        {
            uint8_t *dst = (uint8_t *)TASVIR_ADDR_DATA_RO + offset;
            const uint8_t *src = (uint8_t *)TASVIR_ADDR_DATA_RW + offset;
            tasvir_store_vec_rep(dst, src, len);
        }
        l->changed += len;
    }
    l->cnt = 0;
    size_t bytes_changed = l->changed;
    if (reset_changed)
        l->changed = 0;
    return bytes_changed;
}

size_t tasvir_sync_parse_log(const tasvir_area_desc *__restrict d, size_t offset, size_t len, int pivot) {
    assert(offset % (1 << TASVIR_SHIFT_UNIT) == 0);
    tasvir_sync_list *__restrict sync_l = &ttld.tdata->sync_list;

#ifdef TASVIR_DAEMON
    bool external = pivot;  // internal sync iff pivot == 0
    if (external && d == ttld.root_desc) {
        /* copy root desc unconditionally as it is not properly covered by log (orphan) */
        sync_l->l[sync_l->cnt].offset_scaled = ((uintptr_t)d - TASVIR_ADDR_DATA) >> TASVIR_SHIFT_BIT;
        sync_l->l[sync_l->cnt].len_scaled =
            TASVIR_ALIGNX(sizeof(tasvir_area_desc), (1 << TASVIR_SHIFT_BIT)) >> TASVIR_SHIFT_BIT;
        sync_l->cnt++;
    }
#else
    bool external = false;
    pivot = 0;
#endif
    const __m512i zero_v = _mm512_setzero_si512();
    size_t lbits[2] = {0}; /* number of log bits set to 0 and 1 since last batch of ones */
    size_t lbits1_total = 0;
    size_t offset_scaled = ((uintptr_t)d->h + offset - TASVIR_ADDR_DATA) >> TASVIR_SHIFT_BIT;
    size_t log_unit_start = offset >> TASVIR_SHIFT_UNIT;
    size_t log_units = len >> TASVIR_SHIFT_UNIT;
    tasvir_log_t *__restrict log = external ? d->h->diff_log[0].data : tasvir_data2log(d->h);
    tasvir_log_t *__restrict log_internal = tasvir_area_is_local(d) ? d->h->diff_log[external].data : NULL;

    for (size_t li = log_unit_start; li < log_unit_start + log_units; li += 8) {
        __m512i log_val_v = _mm512_load_si512((__m512i *)&log[li]);
        for (int p = 1; p < pivot; p++) {
            log_val_v = _mm512_or_si512(log_val_v, *(__m512i *)&d->h->diff_log[p].data[li]);
            if (p == 1) /* update the internal log */
                _mm512_store_epi64((__m512i *)&log_internal[li], log_val_v);
        }

        __mmask16 one_mask = _mm512_test_epi64_mask(log_val_v, log_val_v);
        if (!one_mask) { /* skip zero log units */
            lbits[0] += 8 * TASVIR_LOG_UNIT_BITS;
            continue;
        }

        if (log_internal && pivot < 2) /* update the internal log */
            _mm512_store_epi64((__m512i *)&log_internal[li], _mm512_or_si512(log_val_v, *(__m512i *)&log_internal[li]));

        tasvir_log_t log_val_i[8];
        _mm512_store_epi64(log_val_i, log_val_v);
        _mm512_store_epi64((__m512i *)&log[li], zero_v); /* clear out the log */

        /* removes the need to handle the case of last batch being all zeros */
        one_mask |= 1 << 8;
        for (int i = 0; i < 8; i++) {
            uint8_t zcnt = _tzcnt_u32(one_mask >> i);
            if (zcnt) { /* skip zero log units */
                i += zcnt - 1;
                lbits[0] += zcnt * TASVIR_LOG_UNIT_BITS;
                continue;
            }

            /* normal processing per log unit */
            uint8_t lbits_unit_left = TASVIR_LOG_UNIT_BITS;
            bool is_leading_bit_set = log_val_i[i] & (1UL << (TASVIR_LOG_UNIT_BITS - 1));
            do {
                if (is_leading_bit_set && lbits[0]) {
                    if (lbits[1]) {
                        uint8_t *dst = (uint8_t *)TASVIR_ADDR_DATA_RO + ((offset_scaled) << TASVIR_SHIFT_BIT);
                        _mm_prefetch(dst + TASVIR_OFFSET_RO2RW, _MM_HINT_T0);
                        _mm_prefetch(dst, _MM_HINT_T1);
                    }

                    /* NOTE: doing possibly redundant work to avoid branching */
                    /* copy for the previous batch of ones */
                    sync_l->l[sync_l->cnt].offset_scaled = offset_scaled;
                    sync_l->l[sync_l->cnt].len_scaled = lbits[1];
                    /* only if there actually was any change */
                    sync_l->cnt += (bool)lbits[1];
                    /* move the pointers to the head of current batch of ones */
                    offset_scaled += lbits[0] + lbits[1];
                    lbits1_total += lbits[1];
                    lbits[0] = 0;
                    lbits[1] = 0;
                }
                uint8_t lbits_same = _lzcnt_u64(is_leading_bit_set ? ~log_val_i[i] : log_val_i[i]);
                lbits_same = MIN(lbits_unit_left, lbits_same);
                lbits[is_leading_bit_set] += lbits_same;
                lbits_unit_left -= lbits_same;
                log_val_i[i] <<= lbits_same;  // undefined behavior (shift by 64) is fine
                is_leading_bit_set = !is_leading_bit_set;
            } while (lbits_unit_left > 0);
        }

        TASVIR_STATIC_ASSERT(TASVIR_SYNC_LIST_LEN / 2 >= 64, "TASVIR_SYNC_LIST_LEN must have at least 128 elements");
        if (sync_l->cnt >= TASVIR_SYNC_LIST_LEN / 2)
            tasvir_sync_process_changes(d, false, external);
    }

    /* copy for the last batch of ones */
    if (lbits[1]) {
        lbits1_total += lbits[1];
        sync_l->l[sync_l->cnt].offset_scaled = offset_scaled;
        sync_l->l[sync_l->cnt].len_scaled = lbits[1];
        sync_l->cnt++;
    }
    if (external && lbits1_total) {
        tasvir_sync_process_changes(d, true, external);
        d->h->diff_log[1].version_end = d->h->diff_log[0].version_start = d->h->diff_log[0].version_end;
        d->h->diff_log[1].end_us = d->h->diff_log[0].start_us = d->h->diff_log[0].end_us;
    }

    return lbits1_total << TASVIR_SHIFT_BIT;
}
