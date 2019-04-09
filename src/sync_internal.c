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
    j->done = false;
    j->admit = true;
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
    ttld.ndata->job_bytes /= nr_threads * 10;
    ttld.ndata->job_bytes &= ~((1UL << (TASVIR_SHIFT_BYTE + 9)) - 1);
    ttld.ndata->job_bytes = MAX(ttld.ndata->job_bytes, 1 << (TASVIR_SHIFT_BYTE + 9));

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

static size_t tasvir_sync_internal_job_helper(uint8_t *__restrict src, tasvir_log_t *__restrict log_internal,
                                              const size_t len, const bool is_rw) {
    tasvir_log_t *__restrict log = tasvir_data2logunit(src);
    uint8_t *__restrict dst = is_rw ? tasvir_data2shadow(src) : src;
    src = is_rw ? src : tasvir_data2shadow(src);
    src = __builtin_assume_aligned(src, 1 << TASVIR_SHIFT_UNIT);
    dst = __builtin_assume_aligned(dst, 1 << TASVIR_SHIFT_UNIT);

    size_t lbits0 = 0; /* number of 0 log bits since last batch of ones */
    size_t lbits1 = 0; /* number of 1 log bits since last batch of ones */
    size_t bytes_changed = 0;
    size_t lunits_left = len >> TASVIR_SHIFT_UNIT;

    for (; lunits_left > 0; lunits_left -= 8, log += 8) {
        __m512i log_val_v = _mm512_load_si512((__m512i *)log);
        __mmask8 one_mask = _mm512_test_epi64_mask(log_val_v, log_val_v);

        /* add changes to the external log */
        if (log_internal) {
            if (!one_mask)
                _mm512_mask_store_epi64((__m512i *)log_internal, one_mask,
                                        _mm512_or_si512(log_val_v, *(__m512i *)log_internal));
            log_internal += 8;
        }

        /* skip zero log units */
        if (!one_mask) {
            lbits0 += 8 * TASVIR_LOG_UNIT_BITS;
            continue;
        }

        /* zero out log */
        _mm512_mask_store_epi64((__m512i *)log, one_mask, _mm512_setzero_si512());

        tasvir_log_t log_val_i[8];
        _mm512_mask_store_epi64(log_val_i, one_mask, log_val_v);
        for (int i = 0; i < 8; i++) {
            tasvir_log_t log_val = log_val_i[i];
            uint8_t zcnt = _tzcnt_u32(one_mask);
            if (zcnt) {
                /* skip zero log units */
                zcnt = MIN(zcnt, 8 - i);
                one_mask >>= zcnt;
                lbits0 += zcnt * TASVIR_LOG_UNIT_BITS;
                i += zcnt - 1;
                continue;
            } else if (log_val == ~(tasvir_log_t)0 && !lbits0) {
                /* skip fully changed log units when no changes are pending */
                one_mask >>= 1;
                lbits1 += TASVIR_LOG_UNIT_BITS;
                continue;
            }
            one_mask >>= 1;

            /* normal processing per log unit */
            uint8_t lbits_unit_left = TASVIR_LOG_UNIT_BITS;
            do {
                uint8_t lbits_same = _lzcnt_u64(log_val);
                if (lbits_same) {
                    /* skip zero bits */
                    lbits_same = MIN(lbits_unit_left, lbits_same);
                    lbits0 += lbits_same;
                } else {
                    if (lbits0) {
                        size_t bytes_processed = 0;
                        if (lbits1) {
                            /* copy for the previous batch of ones */
                            bytes_processed = lbits1 << TASVIR_SHIFT_BIT;
                            // if (!((is_rw && src >= 0x100000030000) || (!is_rw && dst >= 0x100000030000)))
                            tasvir_store_vec_rep(dst, src, bytes_processed);
                            // memcpy(dst, src, bytes_processed);
                            bytes_changed += bytes_processed;
                            lbits1 = 0;
                        }
                        /* move the pointers to the head of current batch of ones */
                        bytes_processed += lbits0 << TASVIR_SHIFT_BIT;
                        src += bytes_processed;
                        dst += bytes_processed;
                        lbits0 = 0;
                    }
                    lbits_same = _lzcnt_u64(~log_val);
                    lbits1 += lbits_same;
                }
                /* undefined behavior with lbits_same == 64 is fine as we reset log_val anyways */
                log_val <<= lbits_same;
                lbits_unit_left -= lbits_same;
            } while (lbits_unit_left > 0);
        }
    }

    if (lbits1) {
        size_t bytes_processed = lbits1 << TASVIR_SHIFT_BIT;
        // if (!((is_rw && src >= 0x100000030000) || (!is_rw && dst >= 0x100000030000)))
        tasvir_store_vec_rep(dst, src, bytes_processed);
        // memcpy(dst, src, bytes_processed);
        bytes_changed += bytes_processed;
    }

    return bytes_changed;
}

/* returns true if the job is done */
static bool tasvir_sync_internal_job(tasvir_sync_job *j) {
    if (j->done)
        return true;
    if (!j->admit)
        return false;

    size_t seen = 0;
    size_t updated = 0;
    size_t offset;
    size_t len;
    bool is_rw = tasvir_area_is_mapped_rw(j->d);
    bool is_local = tasvir_area_is_local(j->d);
    tasvir_area_header *h_rw = is_rw ? j->d->h : tasvir_data2shadow(j->d->h);
    tasvir_log_t *log_base = is_local ? h_rw->diff_log[0].data : NULL;
    size_t job_bytes = ttld.ndata->job_bytes;

    while ((offset = atomic_fetch_add_explicit(&j->offset, job_bytes, memory_order_relaxed)) < j->d->offset_log_end) {
        len = MIN(job_bytes, j->d->offset_log_end - offset);
        tasvir_log_t *log = log_base ? log_base + (offset >> TASVIR_SHIFT_UNIT) : NULL;
        updated += tasvir_sync_internal_job_helper((uint8_t *)j->d->h + offset, log, len, is_rw);
        seen += len;
    }

    if (j->admit)
        j->admit = false;

    if (seen) {
        if (updated) {
            updated += atomic_fetch_add_explicit(&j->bytes_updated, updated, memory_order_relaxed);
        }
        seen += atomic_fetch_add(&j->bytes_seen, seen);

        if (seen == j->d->offset_log_end) {
            if (is_local && atomic_load_explicit(&j->bytes_updated, memory_order_relaxed)) {
                tasvir_log_t log_val = *log_base;
                tasvir_area_header *h_ro = is_rw ? tasvir_data2shadow(j->d->h) : j->d->h;
                h_ro->time_us = h_rw->time_us = h_ro->diff_log[0].end_us = h_rw->diff_log[0].end_us =
                    ttld.ndata->time_us;
                h_ro->version = h_ro->diff_log[0].version_end = h_rw->diff_log[0].version_end = h_rw->version++;
                h_ro->flags_ = h_rw->flags_ & (TASVIR_AREA_CACHE_ACTIVE | TASVIR_AREA_CACHE_LOCAL);
                *log_base = log_val | 1UL << 62; /* mark second cacheline modified */
            }
            j->done = true;
        }
    }

    return j->done;
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
        // _mm_pause(); /* don't overwhelm the core unnecessarily */
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
    ttld.ndata->last_sync_int_start = tasvir_gettime_us();
#endif
    size_t cur_job;
    _mm_sfence();

    if (!tasvir_barrier_wait()) {
#ifdef TASVIR_DAEMON
        ttld.ndata->stats_cur.failure++;
        ttld.ndata->last_sync_int_end = tasvir_gettime_us();
        ttld.ndata->stats_cur.sync_barrier_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
        ttld.ndata->stats_cur.sync_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
#endif
        ttld.tdata->prev_sync_seq = ttld.tdata->next_sync_seq;
        return -1;
    }

#ifdef TASVIR_DAEMON
    uint64_t time_us = tasvir_gettime_us();
    ttld.ndata->stats_cur.sync_barrier_us += time_us - ttld.ndata->last_sync_int_start;
    /* special case for syncing root desc because it is an orphan */
    /* FIXME: what if root is external? check address mapping when d owner is external */
    /* FIXME: no internal log to capture root desc changes? */
    tasvir_sync_internal_job_helper((uint8_t *)ttld.root_desc, NULL, TASVIR_ALIGN(sizeof(tasvir_area_desc)),
                                    tasvir_area_is_mapped_rw(ttld.root_desc));
    ttld.ndata->sync_req = false;
#endif

    bool done[TASVIR_NR_SYNC_JOBS] = {0};
    bool done_all;
    do {
        done_all = true;
        for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
            /* reduce contention a bit */
            size_t idx = (cur_job + ttld.thread->tid.idx) % ttld.ndata->nr_jobs;
            if (!done[idx]) {
                done[idx] = tasvir_sync_internal_job(&ttld.ndata->jobs[idx]);
                done_all &= done[idx];
            }
        }
    } while (!done_all);

    ttld.tdata->time_us = tasvir_gettime_us();
    ttld.tdata->prev_sync_seq = ttld.tdata->next_sync_seq;
    _mm_sfence();

#ifdef TASVIR_DAEMON
    /* update time */
    ttld.ndata->time_us = ttld.tdata->time_us;
    ttld.ndata->last_sync_int_end = ttld.tdata->time_us;
    /* update statistics */
    ttld.ndata->stats_cur.success++;
    ttld.ndata->stats_cur.sync_us += ttld.tdata->time_us - time_us;
    for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
        ttld.ndata->stats_cur.sync_changed_bytes += ttld.ndata->jobs[cur_job].bytes_updated;
        ttld.ndata->stats_cur.sync_processed_bytes += ttld.ndata->jobs[cur_job].bytes_seen;
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
