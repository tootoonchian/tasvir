#include "tasvir.h"

#define TASVIR_ALIGN_ARG(x) (size_t) TASVIR_ALIGNX(x, sizeof(tasvir_arg_promo_t))

TASVIR_RPCFN_DEFINE(tasvir_init_thread, 0, tasvir_thread *, pid_t)
TASVIR_RPCFN_DEFINE(tasvir_new_alloc_desc, 0, tasvir_area_desc *, tasvir_area_desc)
TASVIR_RPCFN_DEFINE(tasvir_delete, 0, int, tasvir_area_desc *)
TASVIR_RPCFN_DEFINE(tasvir_init_finish, 0, int, tasvir_thread *)
TASVIR_RPCFN_DEFINE(tasvir_update_owner, 0, int, tasvir_area_desc *, tasvir_thread *)
TASVIR_RPCFN_DEFINE(tasvir_area_add_user, 0, int, tasvir_area_desc *, tasvir_node *, int)

void tasvir_init_rpc() {
    TASVIR_RPCFN_REGISTER(tasvir_init_thread);
    TASVIR_RPCFN_REGISTER(tasvir_new_alloc_desc);
    TASVIR_RPCFN_REGISTER(tasvir_delete);
    TASVIR_RPCFN_REGISTER(tasvir_init_finish);
    TASVIR_RPCFN_REGISTER(tasvir_update_owner);
    TASVIR_RPCFN_REGISTER(tasvir_area_add_user);
}

static tasvir_rpc_status *tasvir_vrpc(tasvir_area_desc *d, tasvir_fnptr fnptr, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *m;
    if (rte_mempool_get(ttld.ndata->mp, (void **)&m)) {
        LOG_DBG("rte_mempool_get failed");
        return NULL;
    }

    tasvir_fn_desc *fnd;
    HASH_FIND(h_fnptr, ttld.ht_fnptr, &fnptr, sizeof(fnptr), fnd);
    assert(fnd);

    m->h.dst_tid = d->owner && d->owner->state == TASVIR_THREAD_STATE_RUNNING ? d->owner->tid : ttld.ndata->rpccast_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->boot_tid;
    m->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
    m->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    m->h.d = d;
    m->h.version = d->h ? d->h->version : 0;
    m->fid = fnd->fid;
    ptr = &m->data[TASVIR_ALIGN_ARG(fnd->ret_len)];

    struct tasvir_12b_arg_t {
        uint8_t i[12];
    };
    struct tasvir_64b_arg_t {
        uint8_t i[64];
    };
    struct tasvir_320b_arg_t {
        uint8_t i[320];
    };
    struct tasvir_512b_arg_t {
        uint8_t i[512];
    };

    for (i = 0; i < fnd->argc; i++) {
        ptr = &m->data[fnd->arg_offsets[i]];
        switch (fnd->arg_lens[i]) {
        case 8:
            *(uint64_t *)ptr = va_arg(argp, uint64_t);
            break;
        case 16:
            *(__uint128_t *)ptr = va_arg(argp, __uint128_t);
            break;
        case 12:
            *(struct tasvir_12b_arg_t *)ptr = va_arg(argp, struct tasvir_12b_arg_t);
            break;
        case 64:
            *(struct tasvir_64b_arg_t *)ptr = va_arg(argp, struct tasvir_64b_arg_t);
            break;
        case 320:
            *(struct tasvir_320b_arg_t *)ptr = va_arg(argp, struct tasvir_320b_arg_t);
            break;
        case 512:
            *(struct tasvir_512b_arg_t *)ptr = va_arg(argp, struct tasvir_512b_arg_t);
            break;
        case (sizeof(tasvir_str_static)):
            *(tasvir_str_static *)ptr = va_arg(argp, tasvir_str_static);
            break;
        case (sizeof(tasvir_area_desc)):
            *(tasvir_area_desc *)ptr = va_arg(argp, tasvir_area_desc);
            break;
        default:
            if (fnd->arg_lens[i] <= sizeof(tasvir_arg_promo_t)) {
                *(tasvir_arg_promo_t *)ptr = va_arg(argp, int);
            } else {
                LOG_ERR("missing support for argument of len=%lu. aborting...", fnd->arg_lens[i]);
                abort();
            }
            break;
        }
    }
    m->h.mbuf.pkt_len = m->h.mbuf.data_len =
        TASVIR_ALIGN_ARG((fnd->argc > 0 ? fnd->arg_lens[i - 1] : 0) + ptr - (uint8_t *)&m->h.eh);

    if (tasvir_handle_msg_rpc((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0)
        return NULL;

    if (fnd->flags & TASVIR_FN_NOACK)
        return NULL;

    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    /* garbage collect a previous status */
    if (rs->response)
        rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
    rs->do_free = false;
    rs->id = m->h.id;
    rs->fnd = fnd;
    rs->status = TASVIR_RPC_STATUS_PENDING;
    rs->response = NULL;
    return rs;
}

tasvir_rpc_status *tasvir_rpc(tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc(d, fnptr, argp);
    va_end(argp);
    return rs;
}

int tasvir_rpc_wait(uint64_t timeout_us, void **retval, tasvir_area_desc *d, tasvir_fnptr fnptr, ...) {
    bool done = false;
    bool failed = false;
    uint64_t start_tsc = __rdtsc();
    uint64_t send_tsc = start_tsc;
    uint64_t end_tsc = start_tsc + tasvir_usec2tsc(timeout_us);
    uint64_t resend_diff_tsc = tasvir_usec2tsc(10000);
    uint64_t now_tsc;
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc(d, fnptr, argp);
    va_end(argp);
    if (!rs)
        return -1; /* no response. FIXME: oneway should return 0 */

    int attempts = 100;  // FIXME: for future
    while (!done && !failed && (now_tsc = __rdtsc()) < end_tsc) {
        switch (rs->status) {
        case TASVIR_RPC_STATUS_INVALID:
        case TASVIR_RPC_STATUS_FAILED:
            failed = true;
            break;
        case TASVIR_RPC_STATUS_PENDING:
            if ((now_tsc - send_tsc) > resend_diff_tsc) {
                if (--attempts <= 0) {
                    failed = true;
                    break;
                }
                send_tsc = now_tsc;
                resend_diff_tsc *= 2;
                if (rs->response) {
                    rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
                    rs->response = NULL;
                }
                va_start(argp, fnptr);
                rs = tasvir_vrpc(d, fnptr, argp);
                va_end(argp);
                if (!rs)
                    return -1; /* no response. FIXME: oneway should return 0 */
            }
            break;
        case TASVIR_RPC_STATUS_DONE:
            if (!rs->response || rs->response->h.d != d) {
                LOG_DBG("bad response");
                failed = true;
                break;
            }
            /* FIXME: find a robust way to ensure state is visible. what if attached to writer view? */
            done = !rs->response->h.d || (rs->fnd->flags & TASVIR_FN_NOMODIFY) ||
                   (rs->response->h.d->h && rs->response->h.d->h->version >= rs->response->h.version);
            if (!done) {
                _mm_pause();
            } else if (tasvir_is_booting()) {
                /* a hack to workaround torn writes during boot time */
                tasvir_area_header *h_rw = tasvir_data2rw(rs->response->h.d->h);
                done = !(h_rw->flags_ & TASVIR_AREA_FLAG_EXT_PENDING);
            }
            break;
        default:
            LOG_DBG("invalid rpc status %d", rs->status);
            failed = true;
            break;
        }
        tasvir_service();
    }

    static const char *tasvir_rpc_status_type_str[] = {"invalid", "pending", "failed", "done"};
    if (failed || !done) {
        LOG_ERR("failed d=%s id=%d fn=%s failed=%d done=%d status=%s h=%p v=%lu v_expected=%lu", d ? d->name : NULL,
                rs->id, rs->fnd ? rs->fnd->name : NULL, failed, done, tasvir_rpc_status_type_str[rs->status],
                rs->response ? (void *)rs->response->h.d->h : NULL, rs->response ? rs->response->h.d->h->version : 0,
                rs->response ? rs->response->h.version : 0);
        if (rs->response) {
            rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
            rs->response = NULL;
        }
        return -1;
    }

    if (retval) {
        memcpy(retval, rs->response->data, rs->fnd->ret_len);
    }
    rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
    rs->response = NULL;

    return 0;
}

int tasvir_rpc_fn_register(tasvir_fn_desc *fnd) {
    int i;
    ttld.fn_descs[ttld.nr_fns] = *fnd;
    fnd = &ttld.fn_descs[ttld.nr_fns];
    fnd->fid = ttld.nr_fns;
    ptrdiff_t ptr = TASVIR_ALIGN_ARG(fnd->ret_len);
    for (i = 0; i < fnd->argc; i++) {
        fnd->arg_offsets[i] = ptr;
        ptr += TASVIR_ALIGN_ARG(fnd->arg_lens[i]);
    }
    HASH_ADD(h_fnptr, ttld.ht_fnptr, fnptr, sizeof(fnd->fnptr), &ttld.fn_descs[ttld.nr_fns]);
    ttld.nr_fns++;
    LOG_INFO("name=%s fid=%u argc=%u ret_len=%u", fnd->name, fnd->fid, fnd->argc, fnd->ret_len);
    return 0;
}

void tasvir_handle_msg_rpc_request(tasvir_msg_rpc *m) {
    /* ignore incoming RPC requests at boot time */
    if (tasvir_is_booting()) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return;
    }

    /* FIXME: badly insecure */
    tasvir_fn_desc *fnd = &ttld.fn_descs[m->fid];
    assert(fnd);

    /* execute the function */
    fnd->fnptr_rpc(m->data, fnd->arg_offsets);

    if (fnd->flags & TASVIR_FN_NOACK) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return;
    }

    if (m->h.d->owner != ttld.thread) {
        LOG_ERR("rpc arrived at the wrong thread (d=%s owner=%p me=%p). aborting...", m->h.d->name,
                (void *)m->h.d->owner, (void *)ttld.thread);
        abort();
    }

    /* convert the message into a response */
    m->h.dst_tid = m->h.src_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->boot_tid;
    m->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
    if (m->h.d->h && m->h.version == m->h.d->h->version) {
        LOG_ERR("rpc src and dst at the same version (d=%s v=%lu). aborting...", m->h.d->name, m->h.version);
        abort();
    }
    /* receiver compares msg version with the area version to ensure updates are seen */
    m->h.version = m->h.d->h ? m->h.d->h->version : 0;
    if (tasvir_handle_msg_rpc((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0) {
        LOG_DBG("failed to respond");
    }
}

void tasvir_handle_msg_rpc_response(tasvir_msg_rpc *m) {
    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    rs->status = TASVIR_RPC_STATUS_DONE;
    if (rs->do_free) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        rs->response = NULL;
    } else
        rs->response = m;
}

/* FIXME: not robust */
int tasvir_handle_msg_rpc(tasvir_msg *m, tasvir_msg_src src) {
    bool is_src_me = src == TASVIR_MSG_SRC_ME;
    bool is_dst_local;
    bool is_dst_me;

    // (is_dst_local && (!ttld.thread || m->dst_tid.idx == ttld.thread->tid.idx));
    if (m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        is_dst_local = tasvir_area_is_local(m->d);
        is_dst_me = is_dst_local && m->d->owner == ttld.thread;
    } else if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        is_dst_local = !memcmp(&m->dst_tid.nid, &ttld.ndata->boot_tid.nid, sizeof(tasvir_nid));
        is_dst_me = is_dst_local && (ttld.thread ? !memcmp(&m->dst_tid, &ttld.thread->tid, sizeof(tasvir_tid))
                                                 : !memcmp(&m->dst_tid, &ttld.ndata->boot_tid, sizeof(tasvir_tid)));
    } else {
        LOG_DBG("received an unrecognized message type %d", m->type);
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return -1;
    }
    if (src == TASVIR_MSG_SRC_NET && !is_dst_local) {
        rte_mempool_put(ttld.ndata->mp, (void *)m);
        return -1;
    }

#ifdef TASVIR_DEBUG
    char msg_str[256];
    tasvir_msg_str(m, is_src_me, is_dst_me, msg_str, sizeof(msg_str));
    LOG_DBG("%s", msg_str);
#endif

    /* begin message routing */
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
        tasvir_handle_msg_rpc_request((tasvir_msg_rpc *)m);
    } else if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        tasvir_handle_msg_rpc_response((tasvir_msg_rpc *)m);
    }
    return 0;
}
