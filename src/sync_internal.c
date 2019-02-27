#include "tasvir.h"

#ifdef TASVIR_DAEMON
static inline void tasvir_kill_thread_ownership(tasvir_thread *t, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_area_desc *c = tasvir_data(d);
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &c[i]);
    }
    if (d->owner == t)
        tasvir_update_owner(d, ttld.thread);
}

/* caller contract: is_daemon and tasvir_is_thread_local(t) */
static inline void tasvir_kill_thread(tasvir_thread *t) {
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
    LOG_INFO("tid=%d inactive_time=%zd", t->tid.idx, ttld.ndata->time_us - tdata->time_us);
    rte_ring_free(tdata->ring_rx);
    rte_ring_free(tdata->ring_tx);
    memset(tdata, 0, sizeof(*tdata));
    tdata->state = TASVIR_THREAD_STATE_DEAD;

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttld.root_desc);

    /* kill by pid */
    kill(t->tid.pid, SIGKILL);

    // FIXME: node_desc must deactivate
    t->active = false;
    tasvir_log(&t->active, sizeof(t->active));
}

static size_t tasvir_sched_sync_internal_area(tasvir_area_desc *d) {
    if (!d->owner)
        return 0;

    if (d->sync_int_us < ttld.ndata->sync_int_us) {
        ttld.ndata->sync_int_us = d->sync_int_us;
        LOG_INFO("updating internal sync interval to %luus", ttld.ndata->sync_int_us);
    }

    tasvir_area_header *h_new = tasvir_area_is_mapped_rw(d) ? d->h : tasvir_data2shadow(d->h);
    if (!h_new->active || h_new->private_tag.external_sync_pending) {
        return 0;
    }

    if (ttld.ndata->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
        LOG_ERR("more jobs than free slots");
        abort();
    }
    tasvir_sync_job *j = &ttld.ndata->jobs[ttld.ndata->nr_jobs];
    j->d = d;
    j->done = false;
    atomic_init(&j->offset, 0);
    atomic_init(&j->bytes_seen, 0);
    atomic_init(&j->bytes_updated, 0);

    ttld.ndata->job_bytes += d->offset_log_end;
    ttld.ndata->nr_jobs++;
    return ttld.ndata->job_bytes;
}

static size_t tasvir_health_check() {
    size_t nr_threads = 0;
    /* heartbeat: declare unresponsive threads dead */
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            /* quick check to see if thread is alive */
            /* FIXME: ttld.ndata->time_us - ttld.ndata->tdata[tid].time_us > ttld.node->heartbeat_us */
            if (kill(ttld.node->threads[tid].tid.pid, 0) == -1 && errno == ESRCH) {
                tasvir_kill_thread(&ttld.node->threads[tid]);
                continue;
            }
            nr_threads++;
        }
    }

    return nr_threads;
}

void tasvir_sched_sync_internal() {
    size_t nr_threads = tasvir_health_check();
    ttld.ndata->job_bytes = 0;

    ttld.ndata->barrier_end_tsc = tasvir_rdtsc() + tasvir_usec2tsc(TASVIR_BARRIER_ENTER_US);
    atomic_store(&ttld.ndata->barrier_cnt, nr_threads);

    ttld.ndata->nr_jobs = 0;
    tasvir_walk_areas(ttld.root_desc, &tasvir_sched_sync_internal_area);

    ttld.ndata->job_bytes /= nr_threads * 32;
    ttld.ndata->job_bytes = 1 << __TASVIR_LOG2(ttld.ndata->job_bytes);
    if (ttld.ndata->job_bytes < 64 * 1024)
        ttld.ndata->job_bytes = 64 * 1024;

    /* using tsc as a sync sequence number since it has a healthy gap from the previous one */
    size_t next_sync_seq = ttld.ndata->barrier_end_tsc;
    atomic_store(&ttld.ndata->barrier_seq, next_sync_seq);
    for (size_t tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state == TASVIR_THREAD_STATE_RUNNING) {
            ttld.ndata->tdata[tid].next_sync_seq = next_sync_seq;
        }
    }
}
#endif

static inline size_t tasvir_sync_internal_job_helper(uint8_t *src, tasvir_log_t *log_internal, size_t len, bool is_rw) {
    size_t nr_bits0 = 0;
    size_t nr_bits1 = 0;
    size_t nr_bits1_seen = 0;
    size_t nr_bits_seen = 0;
    size_t nr_bits_total = len >> TASVIR_SHIFT_BIT;
    uint8_t nr_bits_same;
    uint8_t nr_bits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nr_bits_total);

    tasvir_log_t *log = tasvir_data2logunit(src);
    tasvir_log_t log_val = *log;

    uint8_t *dst = is_rw ? tasvir_data2shadow(src) : src;
    src = is_rw ? src : tasvir_data2shadow(src);

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
                    tasvir_mov_blocks_stream(dst, src, nr_bits1 << TASVIR_SHIFT_BIT);
                src += tmp;
                dst += tmp;
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
            if (log_internal) {
                tasvir_log_t log_val = *log_internal;
                *log_internal = log_val | *log;
                log_internal++;
            }
            *log = 0;
            log++;
            log_val = *log;
        }
    }

    if (nr_bits1 > 0) {
        tasvir_mov_blocks_stream(dst, src, nr_bits1 << TASVIR_SHIFT_BIT);
    }

    return nr_bits1_seen << TASVIR_SHIFT_BIT;
}

/* FIXME: expects len to be aligned */
static inline size_t tasvir_sync_internal_job_helper_vector(uint8_t *src, tasvir_log_t *log_internal, size_t len,
                                                            bool is_rw) {
    size_t nr_bits0 = 0;
    size_t nr_bits1 = 0;
    size_t nr_bits1_seen = 0;
    size_t nr_bits_seen = 0;
    size_t nr_bits_total = len >> TASVIR_SHIFT_BIT;
    uint8_t nr_bits_same;
    uint8_t nr_bits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nr_bits_total);
    __m256i zero = _mm256_setzero_si256(), v_log_val, v_log_internal_val;
    int i = 0;

    tasvir_log_t *log = tasvir_data2logunit(src);
    tasvir_log_t *log_val = (tasvir_log_t *)&v_log_val;

    v_log_val = _mm256_stream_load_si256((__m256i *)log);

    if (log_internal) {
        v_log_internal_val = _mm256_stream_load_si256((__m256i *)log_internal);
        v_log_internal_val = _mm256_or_si256(v_log_val, v_log_internal_val);
    }

    uint8_t *dst = is_rw ? tasvir_data2shadow(src) : src;
    src = is_rw ? src : tasvir_data2shadow(src);

    while (nr_bits_total > nr_bits_seen) {
        nr_bits_same = _lzcnt_u64(log_val[i]);
        if (nr_bits_same > 0) {
            nr_bits_same = MIN(nr_bits_unit_left, nr_bits_same);
            nr_bits_seen += nr_bits_same;
            nr_bits0 += nr_bits_same;
            nr_bits_unit_left -= nr_bits_same;
            log_val[i] <<= nr_bits_same;
        }

        if (nr_bits_unit_left > 0) {
            if (nr_bits0 > 0) {
                size_t tmp = (nr_bits0 + nr_bits1) << TASVIR_SHIFT_BIT;
                /* copy over for a previous batch of 1s */
                if (nr_bits1 > 0)
                    tasvir_mov_blocks_stream(dst, src, nr_bits1 << TASVIR_SHIFT_BIT);
                src += tmp;
                dst += tmp;
                nr_bits0 = nr_bits1 = 0;
            }

            nr_bits_same = _lzcnt_u64(~log_val[i]);
            nr_bits_same = MIN(nr_bits_unit_left, nr_bits_same);
            nr_bits_seen += nr_bits_same;
            nr_bits1 += nr_bits_same;
            nr_bits1_seen += nr_bits_same;
            nr_bits_unit_left -= nr_bits_same;
            log_val[i] = (log_val[i] << (nr_bits_same - 1)) << 1;
        }

        if (nr_bits_unit_left == 0) {
            nr_bits_unit_left = MIN(TASVIR_LOG_UNIT_BITS, nr_bits_total - nr_bits_seen);
            if (i == 3) {
                i = 0;
                _mm256_stream_si256((__m256i *)log, zero);
                log += 4;
                v_log_val = _mm256_stream_load_si256((__m256i *)log);
                if (log_internal) {
                    _mm256_stream_si256((__m256i *)log_internal, v_log_internal_val);
                    log_internal += 4;
                    v_log_internal_val = _mm256_stream_load_si256((__m256i *)log_internal);
                    v_log_internal_val = _mm256_or_si256(v_log_val, v_log_internal_val);
                }
            } else {
                i++;
            }
        }
    }

    if (nr_bits1 > 0) {
        tasvir_mov_blocks_stream(dst, src, nr_bits1 << TASVIR_SHIFT_BIT);
    }

    return nr_bits1_seen << TASVIR_SHIFT_BIT;
}

/* returns true if the job is done */
static inline bool tasvir_sync_internal_job(tasvir_sync_job *j) {
    if (j->done)
        return true;

    size_t seen = 0;
    size_t updated = 0;
    size_t offset;
    bool is_rw = tasvir_area_is_mapped_rw(j->d);
    tasvir_area_header *h_new = is_rw ? j->d->h : tasvir_data2shadow(j->d->h);
    tasvir_log_t *log_base = tasvir_area_is_local(j->d) ? h_new->diff_log[0].data : NULL;
    tasvir_log_t *log;

    while ((offset = atomic_fetch_add(&j->offset, ttld.ndata->job_bytes)) < j->d->offset_log_end) {
        size_t len = MIN(ttld.ndata->job_bytes, j->d->offset_log_end - offset);
        seen += len;
        log = log_base ? log_base + (offset >> TASVIR_SHIFT_UNIT) : NULL;
        updated += tasvir_sync_internal_job_helper((uint8_t *)j->d->h + offset, log, len, is_rw);
    }

    if (seen) {
        size_t seen_before = atomic_fetch_add(&j->bytes_seen, seen);
        if (updated)
            updated += atomic_fetch_add(&j->bytes_updated, updated);
        if (seen + seen_before == j->d->offset_log_end) {
            if (tasvir_area_is_local(j->d) &&
                (updated || atomic_load_explicit(&j->bytes_updated, memory_order_relaxed))) {
                tasvir_log_t log_val = *log_base;
                tasvir_area_header *h_old = is_rw ? tasvir_data2shadow(j->d->h) : j->d->h;
                h_old->time_us = h_new->time_us = h_old->diff_log[0].end_us = h_new->diff_log[0].end_us =
                    ttld.ndata->time_us;
                h_old->version = h_old->diff_log[0].version_end = h_new->diff_log[0].version_end = h_new->version++;
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
    ttld.tdata->prev_sync_seq = seq;
    int diff;

    /* last thread */
    if (atomic_fetch_sub(&ttld.ndata->barrier_cnt, 1) == 1) {
        /* (A) if CAS fails another thread must have timed out and caused the barrier to fail, so comply! */
        return atomic_compare_exchange_weak(&ttld.ndata->barrier_seq, &seq, seq + 1);
    }

    while ((diff = atomic_load(&ttld.ndata->barrier_seq) - seq) == 0) {
        _mm_pause(); /* don't overwhelm the core unnecessarily */
        /* (B) a successful timeout is signaled with an increment by two CAS */
        if (tasvir_rdtsc() > ttld.ndata->barrier_end_tsc &&
            atomic_compare_exchange_weak(&ttld.ndata->barrier_seq, &seq, seq + 2)) {
            return false;
        }
    }

    return diff == 1;
}

int tasvir_sync_internal() {
#ifdef TASVIR_DAEMON
    uint64_t time_us = tasvir_gettime_us();
    ttld.ndata->last_sync_int_start = time_us;
#endif

    size_t cur_job;
    _mm_sfence();

    if (!tasvir_barrier_wait()) {
#ifdef TASVIR_DAEMON
        ttld.ndata->stats_cur.failure++;
        uint64_t time_us_end = tasvir_gettime_us();
        ttld.ndata->last_sync_int_end = time_us_end;
        ttld.ndata->stats_cur.sync_barrier_us += time_us_end - time_us;
        ttld.ndata->stats_cur.sync_us += time_us_end - time_us;
#endif
        // LOG_DBG("barrier entry failed");
        return -1;
    }

#ifdef TASVIR_DAEMON
    ttld.ndata->stats_cur.sync_barrier_us += tasvir_gettime_us() - time_us;
    /* special case for syncing root desc because it is an orphan */
    /* FIXME: what if root is external? check address mapping when d owner is external */
    /* FIXME: no internal log to capture root desc changes? */
    tasvir_sync_internal_job_helper((uint8_t *)ttld.root_desc, NULL, TASVIR_ALIGN(sizeof(tasvir_area_desc)),
                                    tasvir_area_is_mapped_rw(ttld.root_desc));
    ttld.ndata->sync_req = false;
#endif

    bool done;
    do {
        done = true;
        for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
            /* reduce contention a bit */
            size_t idx = (cur_job + ttld.thread->tid.idx) % ttld.ndata->nr_jobs;
            done &= tasvir_sync_internal_job(&ttld.ndata->jobs[idx]);
        }
    } while (!done);

    _mm_sfence();
    ttld.tdata->time_us = tasvir_gettime_us();

#ifdef TASVIR_DAEMON
    for (cur_job = 0; cur_job < ttld.ndata->nr_jobs; cur_job++) {
        ttld.ndata->stats_cur.sync_bytes += ttld.ndata->jobs[cur_job].bytes_updated;
    }
    ttld.ndata->time_us = ttld.tdata->time_us;
    ttld.ndata->last_sync_int_end = ttld.tdata->time_us;
    ttld.ndata->stats_cur.success++;
    ttld.ndata->stats_cur.sync_us += ttld.tdata->time_us - time_us;
#endif

    return 0;
}
