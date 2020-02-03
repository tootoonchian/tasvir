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
    if (d->type == TASVIR_AREA_TYPE_CONTAINER)
        for (size_t i = 0; i < d->h->nr_areas; i++)
            tasvir_kill_thread_ownership(t, &d->h->child[i]);
    if (d->owner == t)
        tasvir_update_owner(d, ttld.thread);
}

static void tasvir_kill_thread(tasvir_thread *t /* t is local */) {
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
    LOG_ERR("tid=%d inactive_us=%zd", t->tid.idx, ttld.ndata->time_us - tdata->time_us);

    /* change ownership */
    tasvir_kill_thread_ownership(t, ttld.root_desc);

    /* kill by pid */
    kill(t->tid.pid, SIGKILL);

    /* free resources */
    rte_ring_free(tdata->ring_rx);
    rte_ring_free(tdata->ring_tx);

    /* update thread state */
    memset(tdata, 0, sizeof(*tdata));
    tdata->state = TASVIR_THREAD_STATE_DEAD;

    tasvir_log(t, sizeof(*t));
    memset(t, 0, sizeof(*t));
    t->state = TASVIR_THREAD_STATE_DEAD;
}

static size_t tasvir_sched_sync_internal_area(tasvir_area_desc *d) {
    if (d->sync_int_us < ttld.ndata->sync_int_us) {
        ttld.ndata->sync_int_us = d->sync_int_us;
        LOG_INFO("updating internal sync interval to %luus", ttld.ndata->sync_int_us);
    }

    tasvir_area_header *h_rw = tasvir_data2rw(d->h);
    if (h_rw->flags_ & (TASVIR_AREA_FLAG_EXT_PENDING | TASVIR_AREA_FLAG_SLEEPING))
        return 0;

    if (ttld.ndata->nr_jobs >= TASVIR_NR_SYNC_JOBS) {
        LOG_ERR("more sync jobs than free slots. aborting...");
        abort();
    }
    tasvir_sync_job *j = &ttld.ndata->jobs[ttld.ndata->nr_jobs];
    j->d = d;
    j->owner = d->owner;
    /* FIXME: adjust thresholds per uarch
     * self sync for small areas (<500KB)
     */
    j->self_sync = d->len_logged < 500 * KB;
    j->done_stage1 = false;
    j->done_stage2 = false;
    j->done_stage3 = false;
    j->offset = 0;
    j->bytes_seen = 0;
    j->bytes_updated = 0;

    ttld.ndata->job_bytes += h_rw->flags_ & TASVIR_AREA_FLAG_DYNAMIC ? h_rw->len_dalloc : d->len_logged;
    ttld.ndata->nr_jobs++;
    return ttld.ndata->job_bytes;
}

void tasvir_sched_sync_internal() {
    static bool pending = false;
    if (pending)
        return;
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
                pending = true;
                tasvir_kill_thread(&ttld.node->threads[tid]);
                pending = false;
            } else {
                if (ttld.node->threads[tid].time_us != ttld.ndata->tdata[tid].time_us) {
                    tasvir_log(&ttld.node->threads[tid].time_us, sizeof(ttld.node->threads[tid].time_us));
                    ttld.node->threads[tid].time_us = ttld.ndata->tdata[tid].time_us;
                }
                nr_threads++;
            }
        }
    }

    bool changed = false;
    for (size_t i = 0; i < ttld.node->nr_areas; i++) {
        tasvir_area_desc *d = ttld.node->areas_d[i];
        tasvir_area_header *h_ro = tasvir_data2ro(d->h);
        // FIXME: not quite right due to incomplete/pending updates
        uint64_t v = h_ro->version;
        if (ttld.node->areas_v[i] != v) {
            tasvir_log(&ttld.node->areas_v[i], sizeof(ttld.node->areas_v[i]));
            changed = true;
            ttld.node->areas_v[i] = v;
        }
    }
    if (changed) {
#ifdef TASVIR_DEBUG_PRINT_VIEWS
        tasvir_print_views(ttld.node);
#endif
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

    if (j->self_sync && !is_local_writer)  // non-cooperative sync
        return false;

    if (j->done_stage1)
        return false;

    size_t seen = 0;
    size_t offset;
    size_t job_bytes = ttld.ndata->job_bytes;

    tasvir_area_header *__restrict h_rw = tasvir_data2rw(d->h);
    size_t len_logged = h_rw->flags_ & TASVIR_AREA_FLAG_DYNAMIC ? h_rw->len_dalloc : d->len_logged;

    while (!j->done_stage1 &&
           (offset = atomic_fetch_add_explicit(&j->offset, job_bytes, memory_order_relaxed)) < len_logged) {
        size_t len = MIN(job_bytes, len_logged - offset);
        tasvir_sync_parse_log(d, offset, len, 0);
        seen += len;
    }

    if (!seen)
        return false;

    if (!j->done_stage1)
        j->done_stage1 = true;

    size_t updated = tasvir_sync_process_changes(NULL, true, false);
    if (updated)
        atomic_fetch_add_explicit(&j->bytes_updated, updated, memory_order_relaxed);

    if (seen + atomic_fetch_add(&j->bytes_seen, seen) == len_logged) {
        if (h_rw->flags_ & TASVIR_AREA_FLAG_EXT_ENQUEUE)
            h_rw->flags_ &= ~TASVIR_AREA_FLAG_EXT_ENQUEUE;
        bool has_changes = updated || atomic_load_explicit(&j->bytes_updated, memory_order_relaxed);
        if (has_changes) {
            tasvir_area_header *__restrict h_ro = tasvir_data2ro(d->h);
            if (d->owner != j->owner) {
                if (tasvir_thread_is_local(d->owner)) {
                    h_rw->flags_ |= TASVIR_AREA_FLAG_LOCAL;
                } else {
                    h_rw->flags_ &= ~TASVIR_AREA_FLAG_LOCAL;
                }
            }
            h_ro->flags_ = h_rw->flags_ & (TASVIR_AREA_FLAG_ACTIVE | TASVIR_AREA_FLAG_LOCAL);
            if (is_local) {
                h_ro->time_us = h_ro->diff_log[0].end_us = h_rw->time_us = h_rw->diff_log[0].end_us =
                    ttld.ndata->time_us;
                h_ro->version = h_ro->diff_log[0].version_end = h_rw->diff_log[0].version_end = h_rw->version;
                ++h_rw->version;
                *h_rw->diff_log[0].data |= 1UL << 62; /* mark second cacheline modified */
#ifdef TASVIR_DEBUG_PRINT_VIEWS
                LOG_DBG("d=%s v_rw=%lu v_ro=%lu", d->name, h_rw->version, h_ro->version);
#endif
            }
        } else if (!j->done_stage3) {
            j->done_stage3 = true;
        }
        j->done_stage2 = true;
    }

    return j->done_stage2;
}

static bool tasvir_sync_internal_job_postprocess(tasvir_sync_job *j) {
    const tasvir_area_desc *__restrict d = j->d;
    if (j->owner != d->owner)
        tasvir_update_va(d, d->owner == ttld.thread);
    if (j->done_stage3)
        return true;

    bool is_local_writer = d->owner == ttld.thread;
    if (!is_local_writer)
#ifdef TASVIR_DAEMON
        is_local_writer = !tasvir_area_is_local(d);
#else
        return true;
#endif
    if (is_local_writer) {
        /* FIXME: adjust thresholds per uarch
         * here I should really only reclaim modified lines but tracking them is a bit hard
         */
        size_t log_units = d->len_logged >> TASVIR_SHIFT_UNIT;
        size_t log_bytes = log_units * sizeof(tasvir_log_t);
        /* FIXME: 512KB was experimentally set here but likely function of L2 size and uarch-dependent */
        if (log_bytes < 512 * KB) {
            const size_t jump = TASVIR_CACHELINE_BYTES / sizeof(tasvir_log_t);
            tasvir_log_t *log = tasvir_data2log(d->h);
            for (size_t i = 0; i < log_units; i += jump)
                _mm_prefetch(log + i, _MM_HINT_T1);
        }
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
        ttld.ndata->last_sync_int_end = tasvir_time_us();
        ttld.ndata->stats_cur.isync_failure++;
        ttld.ndata->stats_cur.isync_barrier_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
        ttld.ndata->stats_cur.isync_us += ttld.ndata->last_sync_int_end - ttld.ndata->last_sync_int_start;
#endif
        ttld.tdata->prev_sync_seq = ttld.tdata->next_sync_seq;
        return -1;
    }

#ifdef TASVIR_DAEMON
    uint64_t time_us = tasvir_time_us();
    ttld.ndata->stats_cur.isync_barrier_us += time_us - ttld.ndata->last_sync_int_start;
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
    ttld.ndata->stats_cur.isync_success++;
    ttld.ndata->stats_cur.isync_us += ttld.tdata->time_us - time_us;
    for (cur_job = 0; cur_job < nr_jobs; cur_job++) {
        ttld.ndata->stats_cur.isync_changed_bytes += jobs[cur_job].bytes_updated;
        ttld.ndata->stats_cur.isync_processed_bytes += jobs[cur_job].bytes_seen;
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
