#include "tasvir.h"

TASVIR_RPCFN_DEFINE(tasvir_init_thread, tasvir_thread *, pid_t, uint16_t)
TASVIR_RPCFN_DEFINE(tasvir_new, tasvir_area_desc *, tasvir_area_desc)
TASVIR_RPCFN_DEFINE(tasvir_delete, int, tasvir_area_desc *)
TASVIR_RPCFN_DEFINE(tasvir_init_finish, int, tasvir_thread *)
TASVIR_RPCFN_DEFINE(tasvir_update_owner, int, tasvir_area_desc *, tasvir_thread *)
TASVIR_RPCFN_DEFINE(tasvir_attach_helper, int, tasvir_area_desc *, tasvir_node *)
#ifdef TASVIR_DAEMON
TASVIR_RPCFN_DEFINE(tasvir_sync_external_area, int, tasvir_area_desc *, bool)
#endif


void tasvir_init_rpc() {
    TASVIR_RPCFN_REGISTER(tasvir_init_thread);
    TASVIR_RPCFN_REGISTER(tasvir_new);
    TASVIR_RPCFN_REGISTER(tasvir_delete);
    TASVIR_RPCFN_REGISTER(tasvir_init_finish);
    TASVIR_RPCFN_REGISTER(tasvir_update_owner);
    TASVIR_RPCFN_REGISTER(tasvir_attach_helper);
#ifdef TASVIR_DAEMON
    TASVIR_RPCFN_REGISTER(tasvir_sync_external_area);
#endif
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

    /* FIXME: former case is only at init time for a non-root daemon */
    m->h.dst_tid = d->owner->active ? d->owner->tid : ttld.ndata->rootcast_tid;
    m->h.src_tid = ttld.thread ? ttld.thread->tid : ttld.ndata->nodecast_tid;
    m->h.id = ttld.nr_msgs++ % TASVIR_NR_RPC_MSG;
    m->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    m->h.time_us = d->h ? d->h->update_us : ttld.ndata->time_us;
    m->d = d;
    m->fid = fnd->fid;
    ptr = &m->data[TASVIR_ALIGN_ARG(fnd->ret_len)];

    for (i = 0; i < fnd->argc; i++) {
        ptr = &m->data[fnd->arg_offsets[i]];
        switch (fnd->arg_lens[i]) {
        case 8:
            *(uint64_t *)ptr = va_arg(argp, uint64_t);
            break;
        case 16:
            *(__uint128_t *)ptr = va_arg(argp, __uint128_t);
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
                LOG_ERR("missing support for argument of len=%lu", fnd->arg_lens[i]);
                abort();
            }
            break;
        }
    }
    m->h.mbuf.pkt_len = m->h.mbuf.data_len =
        TASVIR_ALIGN_ARG((fnd->argc > 0 ? fnd->arg_lens[i - 1] : 0) + ptr - (uint8_t *)&m->h.eh);

    if (tasvir_service_msg((tasvir_msg *)m, TASVIR_MSG_SRC_ME) != 0)
        return NULL;

    if (fnd->oneway)
        return NULL;

    tasvir_rpc_status *rs = &ttld.status_l[m->h.id];
    /* garbage collect a previous status */
    if (rs->response)
        rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
    rs->do_free = false;
    rs->id = m->h.id;
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
    uint64_t end_tsc = tasvir_rdtsc() + tasvir_usec2tsc(timeout_us);
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *rs = tasvir_vrpc(d, fnptr, argp);
    va_end(argp);
    if (!rs)
        return -1; /* no response. FIXME: oneway should return 0 */

    while (tasvir_rdtsc() < end_tsc && !done && !failed) {
        switch (rs->status) {
        case TASVIR_RPC_STATUS_INVALID:
        case TASVIR_RPC_STATUS_FAILED:
            failed = true;
            break;
        case TASVIR_RPC_STATUS_PENDING:
            break;
        case TASVIR_RPC_STATUS_DONE:
            if (!rs->response) {
                LOG_DBG("bad response");
                failed = true;
                break;
            }
            /* FIXME: find a better way to ensure state is visible. what if attached to writer view? */
            /* FIXME: useless if rpc is not to update the area */
            done = !rs->response->d ||
                   (rs->response->d->h->active && rs->response->d->h->update_us >= rs->response->h.time_us);
            /* a hack to workaround torn writes during boot time */
            if (unlikely(done && !ttld.thread)) {
                done = !rs->response->d->h->private_tag.external_sync_pending;
            }
            break;
        default:
            LOG_DBG("invalid rpc status %d", rs->status);
            failed = true;
        }
        tasvir_service();
    }

    if (failed || !done) {
        static const char *tasvir_rpc_status_type_str[] = {"invalid", "pending", "failed", "done"};
        if (rs->response)
            rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
        LOG_INFO("failed (failed=%d done=%d status=%s h=%p update_us=%lu expected_us=%lu)", failed, done,
                 tasvir_rpc_status_type_str[rs->status], rs->response ? (void *)rs->response->d->h : NULL,
                 rs->response ? rs->response->d->h->update_us : 0, rs->response ? rs->response->h.time_us : 0);
        return -1;
    }

    if (retval) {
        /* FIXME: badly insecure */
        tasvir_fn_desc *fnd = &ttld.fn_descs[rs->response->fid];
        memcpy(retval, rs->response->data, fnd->ret_len);
    }
    rte_mempool_put(ttld.ndata->mp, (void *)rs->response);
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

