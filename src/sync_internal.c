#include "tasvir.h"

void tasvir_activate(bool active) {
    if (active) {
        ttld.tdata->state_req = TASVIR_THREAD_STATE_RUNNING;
        while (ttld.tdata->state != ttld.tdata->state_req) {
            _mm_pause();
        }
    } else {
        ttld.tdata->state_req = TASVIR_THREAD_STATE_SLEEPING;
        /* FIXME: without waiting we are risking a potential internal sync failure */
    }
}

#ifdef TASVIR_DAEMON
static void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c[i]);
    }
    if (d->owner == t)
        tasvir_update_owner(d, ttld.thread);
}

/* t must be local */
static void tasvir_kill_thread(tasvir_thread *t) {
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
    LOG_INFO("tid=%d inactive_us=%zd", t->tid.idx, ttld.ndata->time_us - tdata->time_us);
    rte_ring_free(tdata->ring_rx);
    rte_ring_free(tdata->ring_tx);
    memset(tdata, 0, sizeof(*tdata));
    tdata->state = TASVIR_THREAD_STATE_DEAD;

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttld.root_desc);

    /* kill by pid */
    kill(t->tid.pid, SIGKILL);

    memset(t, 0, sizeof(*t));
    t->state = TASVIR_THREAD_STATE_DEAD;
    tasvir_log(t, sizeof(*t));
}

static size_t tasvir_sched_sync_internal_area(tasvir_area_desc *d) {
    if (d->sync_int_us < ttld.ndata->sync_int_us) {
        ttld.ndata->sync_int_us = d->sync_int_us;
        LOG_INFO("updating internal sync interval to %luus", ttld.ndata->sync_int_us);
    }

    tasvir_area_header *h_new = tasvir_area_is_mapped_rw(d) ? d->h : tasvir_data2shadow(d->h);
    // if (!h_new->d->h || (h_new->flags_ & TASVIR_AREA_CACHE_NETUPDATE) || (h_new->flags_ &
    // TASVIR_AREA_CACHE_SLEEPING)) {
    if ((h_new->flags_ & TASVIR_AREA_CACHE_NETUPDATE) || (h_new->flags_ & TASVIR_AREA_CACHE_SLEEPING)) {
        return 0;
    }

    if (ttld.ndata->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
        LOG_ERR("more jobs than free slots");
        abort();
    }
    tasvir_sync_job *j = &ttld.ndata->jobs[ttld.ndata->nr_jobs];
    j->d = d;
    /* FIXME: adjust thresholds per uarch
     * self sync for small areas (<500KB)
     */
    j->self_sync = d->offset_log_end < 500 * KB;
    j->done_stage1 = false;
    j->done_stage2 = false;
    /* FIXME: adjust thresholds per uarch
     * zero out log during processing for large areas (>200MB)
     * otherwise, the local writer will zero out the log after sync
     */
    j->done_stage3 = d->offset_log_end > 200 * MB;
    j->offset = 0;
    j->bytes_seen = 0;
    j->bytes_updated = 0;

    ttld.ndata->job_bytes += d->offset_log_end;
    ttld.ndata->nr_jobs++;
    return ttld.ndata->job_bytes;
}

void tasvir_sched_sync_internal() {
    size_t nr_threads = 0;
    /* heartbeat: declare unresponsive threads dead */
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state_req != TASVIR_THREAD_STATE_INVALID &&
            ttld.ndata->tdata[tid].state != ttld.ndata->tdata[tid].state_req) {
            ttld.ndata->tdata[tid].state = ttld.ndata->tdata[tid].state_req;
        }

        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            /* quick check to see if thread is alive */
            if (ttld.ndata->time_us - ttld.ndata->tdata[tid].time_us > ttld.node->heartbeat_us &&
                kill(ttld.node->threads[tid].tid.pid, 0) == -1 && errno == ESRCH) {
                tasvir_kill_thread(&ttld.node->threads[tid]);
            } else {
                nr_threads++;
            }
        }
    }

    ttld.ndata->nr_jobs = 0;
    ttld.ndata->job_bytes = 0;
    tasvir_area_walk(ttld.root_desc, &tasvir_sched_sync_internal_area);
    ttld.ndata->job_bytes /= nr_threads * 8;
    ttld.ndata->job_bytes &= ~(TASVIR_ALIGNMENT - 1);
    ttld.ndata->job_bytes = MAX(ttld.ndata->job_bytes, TASVIR_ALIGNMENT * 4);

    /* using tsc as sync sequence number since it has a healthy gap from the previous one */
    ttld.ndata->barrier_end_tsc = __rdtsc() + tasvir_usec2tsc(TASVIR_BARRIER_ENTER_US);
    ttld.ndata->barrier_cnt = nr_threads;
    size_t next_sync_seq = ttld.ndata->barrier_end_tsc;
    ttld.ndata->barrier_seq = next_sync_seq;
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            ttld.ndata->tdata[tid].next_sync_seq = next_sync_seq;
        }
    }
}
#endif

static size_t tasvir_sync_copy_changes(bool reset_changed) {
    tasvir_sync_list *__restrict l = &ttld.ndata->sync_list[ttld.thread->tid.idx];
    /* src is TASVIR_OFFSET_SHADOW apart from dst */
    uint8_t *dst_base = (uint8_t *)TASVIR_ADDR_DATA2;

    int i;
    /* prefetch distance and depth */
    const int distance = 64;
    const int depth = 8;
    for (i = 0; i < l->cnt - distance; i += depth) {
        for (int j = i + distance; j < i + distance + depth; j++) {
            uint8_t *dst = dst_base + (l->l[j].offset_scaled << TASVIR_SHIFT_BIT);
            _mm_prefetch(dst + TASVIR_OFFSET_SHADOW, _MM_HINT_T0);
            _mm_prefetch(dst, _MM_HINT_ET0);
        }
        for (int j = i; j < i + depth; j++) {
            uint8_t *dst = dst_base + (l->l[j].offset_scaled << TASVIR_SHIFT_BIT);
            size_t len = l->l[j].len_scaled << TASVIR_SHIFT_BIT;
            tasvir_store_vec_rep(dst, dst + TASVIR_OFFSET_SHADOW, len);
            l->changed += len;
        }
    }
    for (; i < l->cnt; i++) {
        uint8_t *dst = dst_base + (l->l[i].offset_scaled << TASVIR_SHIFT_BIT);
        size_t len = l->l[i].len_scaled << TASVIR_SHIFT_BIT;
        tasvir_store_vec_rep(dst, dst + TASVIR_OFFSET_SHADOW, len);
        l->changed += len;
    }
    l->cnt = 0;

    size_t bytes_changed = l->changed;
    if (reset_changed)
        l->changed = 0;
    return bytes_changed;
}

static void tasvir_sync_parse_log(uint8_t *base, tasvir_log_t *__restrict log_internal, size_t len, bool reset_log) {
    tasvir_log_t *__restrict log = tasvir_data2log(base);
    const __m512i zero_v = _mm512_setzero_si512();

    size_t lbits[2] = {0}; /* number of log bits set to 0 and 1 since last batch of ones */
    // bool skip = tasvir_time_boot_us() > 8 * S2US;
    tasvir_sync_list *__restrict sync_l = &ttld.ndata->sync_list[ttld.thread->tid.idx];
    size_t offset_scaled = ((uintptr_t)base - TASVIR_ADDR_DATA) >> TASVIR_SHIFT_BIT;

    for (; len > 0; len -= 8 << TASVIR_SHIFT_UNIT, log += 8, log_internal += (bool)log_internal * 8) {
        __m512i log_val_v = _mm512_load_si512((__m512i *)log);
        __mmask16 one_mask = _mm512_test_epi64_mask(log_val_v, log_val_v);

        /* skip all-zero log units */
        if (!one_mask) {
            lbits[0] += 8 * TASVIR_LOG_UNIT_BITS;
            continue;
        }

        tasvir_log_t log_val_i[8];
        _mm512_store_epi64(log_val_i, log_val_v);

        /* clear out the log and add changes to the internal log */
        if (reset_log) {
            _mm512_store_epi64((__m512i *)log, zero_v);
            _mm_prefetch(log, _MM_HINT_T2);
        }

        if (log_internal)
            _mm512_store_epi64((__m512i *)log_internal, _mm512_or_si512(log_val_v, *(__m512i *)log_internal));

        // removes the need to handle the case of last batch being all zeros
        one_mask |= (1 << 8);
        for (int i = 0; i < 8; i++) {
            uint8_t zcnt = _tzcnt_u32(one_mask >> i);
            if (zcnt) {
                /* skip zero log units */
                i += zcnt - 1;
                lbits[0] += zcnt * TASVIR_LOG_UNIT_BITS;
                continue;
            }

            /* normal processing per log unit */
            uint8_t lbits_unit_left = TASVIR_LOG_UNIT_BITS;
            bool is_leading_bit_set = log_val_i[i] & (1UL << (TASVIR_LOG_UNIT_BITS - 1));
            do {
                if (is_leading_bit_set && lbits[0]) {
                    /* NOTE: doing possibly redundant work to avoid branching */
                    /* copy for the previous batch of ones */
                    sync_l->l[sync_l->cnt].offset_scaled = offset_scaled;
                    sync_l->l[sync_l->cnt].len_scaled = lbits[1];
                    /* only if there actually was any change */
                    sync_l->cnt += (bool)lbits[1];
                    /* move the pointers to the head of current batch of ones */
                    offset_scaled += lbits[0] + lbits[1];
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

        /*
        if (sync_l->cnt >= 1024) {
            tasvir_sync_copy_changes(false);
        }*/
    }

    /* copy for the last batch of ones */
    sync_l->l[sync_l->cnt].offset_scaled = offset_scaled;
    sync_l->l[sync_l->cnt].len_scaled = lbits[1];
    sync_l->cnt += (bool)lbits[1];

    if (sync_l->cnt > TASVIR_CHANGES_PER_SYNC) {
        LOG_ERR("insufficient room in the thread-local publication list");
        abort();
    }
}

/* returns true if the job is done */
static bool tasvir_sync_internal_job(tasvir_sync_job *j) {
    const tasvir_area_desc *__restrict d = j->d;
    bool is_local = tasvir_area_is_local(d);
    bool is_local_writer = d->owner == ttld.thread;
#ifdef TASVIR_DAEMON
    if (!is_local_writer)
        is_local_writer = !is_local;
#endif

    if (j->done_stage2)
        return true;

    // non-cooperative sync
    if (j->self_sync && !is_local_writer)
        return false;

    if (j->done_stage1)
        return false;

    /* give a chance (3 rounds) to area owners to do sync on their own for better performance/locality */
    // if (attempt < 3 && !is_local_writer)
    //     return false;

    size_t seen = 0;
    size_t offset;
    size_t job_bytes = ttld.ndata->job_bytes;

    tasvir_area_header *__restrict h_rw = tasvir_data2rw(d->h);
    tasvir_log_t *__restrict log_internal_base = is_local ? h_rw->diff_log[0].data : NULL;
    tasvir_log_t *__restrict log_internal = NULL;

    while (!j->done_stage1 &&
           (offset = atomic_fetch_add_explicit(&j->offset, job_bytes, memory_order_relaxed)) < d->offset_log_end) {
        if (is_local)
            log_internal = log_internal_base + (offset >> TASVIR_SHIFT_UNIT);
        size_t len = MIN(job_bytes, d->offset_log_end - offset);
        tasvir_sync_parse_log((uint8_t *)d->h + offset, log_internal, len, j->done_stage3);
        seen += len;
    }

    if (!seen)
        return false;

    if (!j->done_stage1)
        j->done_stage1 = true;

    size_t updated = tasvir_sync_copy_changes(true);
    if (updated)
        atomic_fetch_add_explicit(&j->bytes_updated, updated, memory_order_relaxed);

    if (seen + atomic_fetch_add(&j->bytes_seen, seen) == d->offset_log_end) {
        bool has_changes = updated || atomic_load_explicit(&j->bytes_updated, memory_order_relaxed);
        if (!has_changes) {
            if (!j->done_stage3)
                j->done_stage3 = true;
        } else if (is_local) {
            tasvir_area_header *__restrict h_ro = tasvir_data2ro(d->h);
            h_ro->time_us = h_ro->diff_log[0].end_us = h_rw->time_us = h_rw->diff_log[0].end_us = ttld.ndata->time_us;
            h_ro->version = h_ro->diff_log[0].version_end = h_rw->diff_log[0].version_end = h_rw->version;
            h_ro->flags_ = h_rw->flags_ & (TASVIR_AREA_CACHE_ACTIVE | TASVIR_AREA_CACHE_LOCAL);
            ++h_rw->version;
            *log_internal_base |= 1UL << 62; /* mark second cacheline modified */
        }
        j->done_stage2 = true;
    }

    return j->done_stage2;
}

static bool tasvir_sync_internal_job_postprocess(tasvir_sync_job *j) {
    if (j->done_stage3)
        return true;

    const tasvir_area_desc *__restrict d = j->d;
    bool is_local_writer = d->owner == ttld.thread;
    if (!is_local_writer)
#ifdef TASVIR_DAEMON
        is_local_writer = !tasvir_area_is_local(d);
#else
        return true;
#endif
    if (is_local_writer) {
        const __m512i zero_v = _mm512_setzero_si512();
        size_t log_units = d->offset_log_end >> TASVIR_SHIFT_UNIT;
        tasvir_log_t *log = tasvir_data2log(d->h);
        tasvir_log_t *log_end = log + log_units;
        do {
            __m512i log_val_v = _mm512_load_si512((__m512i *)log);
            __mmask8 one_mask = _mm512_test_epi64_mask(log_val_v, log_val_v);
            if (one_mask)
                _mm512_mask_store_epi64((__m512i *)log, one_mask, zero_v);
            log += 8;
        } while (log < log_end);
        j->done_stage3 = true;
    }

    return j->done_stage3;
}

static bool tasvir_barrier_wait() {
    /* using seq guarantees that barrier succeeds iff all threads are on the same seq */
    size_t seq = ttld.tdata->next_sync_seq;
    size_t seq_d = ttld.ndata->barrier_seq;
    int diff;

    /* on correct sync */
    if (seq != seq_d) {
        return false;
    }

    /* last thread */
    if (atomic_fetch_sub(&ttld.ndata->barrier_cnt, 1) == 1) {
        /* (A) if CAS fails another thread must have timed out and caused the barrier to fail, so comply! */
        return atomic_compare_exchange_strong(&ttld.ndata->barrier_seq, &seq, seq + 1);
    }

    /* wait until success or timeout */
    while ((diff = ttld.ndata->barrier_seq - seq) == 0) {
        rte_delay_us_block(2); /* don't overwhelm the core unnecessarily */
        /* (B) a successful timeout is signaled with an increment by two CAS */
        if (__rdtsc() > ttld.ndata->barrier_end_tsc) {
            if (atomic_compare_exchange_weak(&ttld.ndata->barrier_seq, &seq, seq + 2)) {
                return false;
            }
            seq = seq_d;
        }
    }

    /* 1 is success, 2 is timeout, >2 is incorrect sync seq */
    return diff == 1;
}

int tasvir_sync_internal() {
#ifdef TASVIR_DAEMON
    ttld.ndata->last_sync_int_start = tasvir_time_us();
#endif
    size_t cur_job;
    _mm_sfence();

    if (!tasvir_barrier_wait()) {
#ifdef TASVIR_DAEMON
        ttld.ndata->stats_cur.failure++;
        ttld.ndata->last_sync_int_end = tasvir_time_us();
        ttld.ndata->stats_cur.sync_barrier_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
        ttld.ndata->stats_cur.sync_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
#endif
        ttld.tdata->prev_sync_seq = ttld.tdata->next_sync_seq;
        return -1;
    }

#ifdef TASVIR_DAEMON
    uint64_t time_us = tasvir_time_us();
    ttld.ndata->stats_cur.sync_barrier_us += time_us - ttld.ndata->last_sync_int_start;
    /* special case for syncing root desc because it is an orphan */
    /* FIXME: what if root is external? check address mapping when d owner is external */
    /* FIXME: no internal log to capture root desc changes? */
    tasvir_sync_parse_log((uint8_t *)ttld.root_desc, NULL, TASVIR_ALIGN(sizeof(tasvir_area_desc)), true);
    tasvir_sync_copy_changes(true);
    ttld.ndata->sync_req = false;
#endif

    tasvir_sync_job *__restrict jobs = ttld.ndata->jobs;
    size_t nr_jobs = ttld.ndata->nr_jobs;
    bool done[TASVIR_NR_SYNC_JOBS] = {0};
    bool done_all = false;
    while (!done_all) {
        done_all = true;
        for (cur_job = 0; cur_job < nr_jobs; cur_job++) {
            tasvir_sync_job *__restrict j = &jobs[cur_job];
            if (!done[cur_job])
                done[cur_job] = tasvir_sync_internal_job(j) && tasvir_sync_internal_job_postprocess(j);
            done_all &= done[cur_job];
        }
    }

    ttld.tdata->time_us = tasvir_time_us();
    ttld.tdata->prev_sync_seq = ttld.tdata->next_sync_seq;
    _mm_sfence();

#ifdef TASVIR_DAEMON
    /* update time */
    ttld.ndata->time_us = ttld.tdata->time_us;
    ttld.ndata->last_sync_int_end = ttld.tdata->time_us;
    /* update statistics */
    ttld.ndata->stats_cur.success++;
    ttld.ndata->stats_cur.sync_us += ttld.tdata->time_us - time_us;
    for (cur_job = 0; cur_job < nr_jobs; cur_job++) {
        ttld.ndata->stats_cur.sync_changed_bytes += jobs[cur_job].bytes_updated;
        ttld.ndata->stats_cur.sync_processed_bytes += jobs[cur_job].bytes_seen;
    }

    uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(ttld.node->heartbeat_us);
    /* wait until all threads are done */
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            bool failed;
            while ((failed = ttld.ndata->tdata[tid].next_sync_seq != ttld.ndata->tdata[tid].prev_sync_seq)) {
                if (__rdtsc() > end_tsc) {
                    LOG_ERR("Thread %lu did not finish sync. tseq_prev=%lu tseq_cur=%lu vs %lu %lu", tid,
                            ttld.ndata->tdata[tid].prev_sync_seq, ttld.ndata->tdata[tid].next_sync_seq,
                            ttld.ndata->tdata[0].prev_sync_seq, ttld.ndata->tdata[0].next_sync_seq);
                    break;
                }
                _mm_pause();
            }
            if (failed) {
                tasvir_kill_thread(&ttld.node->threads[tid]);
            }
        }
    }
#endif

    return 0;
}
