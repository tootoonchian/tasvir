#include "tasvir.h"

void tasvir_area_activate(tasvir_area_desc *d, bool active) {
    if (tasvir_area_is_active(d) && tasvir_area_is_mapped_rw(d)) {
        if (active && (d->h->flags_ & TASVIR_AREA_FLAG_SLEEPING)) {
            d->h->flags_ &= ~TASVIR_AREA_FLAG_SLEEPING;
            LOG_DBG("activating area %s", d->name);
        } else if (!active && !(d->h->flags_ & TASVIR_AREA_FLAG_SLEEPING)) {
            d->h->flags_ |= TASVIR_AREA_FLAG_SLEEPING;
            LOG_DBG("deactivating area %s", d->name);
        }
    }
}

tasvir_area_desc *tasvir_area_get_by_name(tasvir_area_desc *pd, const char *name) {
    tasvir_area_desc *d = NULL;
    if (pd == NULL) {
        if (name[0] == '/')
            d = ttld.root_desc;
    } else if (pd->type == TASVIR_AREA_TYPE_CONTAINER && pd->h && pd->h->d) {
        for (size_t i = 0; i < pd->h->nr_areas; i++) {
            if (strncmp(pd->h->child[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &pd->h->child[i];
                break;
            }
        }
    }

    return d;
}

bool tasvir_area_is_active(const tasvir_area_desc *d) {
    return d && d->owner && d->h && (d->h->flags_ & TASVIR_AREA_FLAG_ACTIVE);
}

bool tasvir_area_is_active_local(const tasvir_area_desc *d) {
    tasvir_area_header *h_rw = tasvir_data2rw(d->h);
    return d && d->owner && d->h && (h_rw->flags_ & TASVIR_AREA_FLAG_ACTIVE);
}

bool tasvir_area_is_attached(const tasvir_area_desc *d, const tasvir_node *node) {
    if (!ttld.node) {
        /* node must also be null since no incoming RPC is allowed and node in initialized with ttld.node */
        assert(!node);
        /* root and local node areas are the only ones attached to at boot time */
        assert(d == ttld.root_desc || d->type == TASVIR_AREA_TYPE_NODE);
#ifdef TASVIR_DAEMON
        return (d == ttld.root_desc && d->owner) || (d->type == TASVIR_AREA_TYPE_NODE);
#else
        return true;
#endif
    }

    if (node && tasvir_area_is_active(d)) {
        for (size_t i = 0; i < d->h->nr_users; i++) {
            if (d->h->users[i].node == node)
                return true;
        }
    }
    return false;
}

bool tasvir_area_is_local(const tasvir_area_desc *d) { return d->h && (d->h->flags_ & TASVIR_AREA_FLAG_LOCAL); }

bool tasvir_area_is_local_by_tid(const tasvir_area_desc *d) {
    return memcmp(&d->owner->tid.nid, &ttld.node->nid, sizeof(tasvir_nid)) == 0;
}

bool tasvir_area_is_mapped_rw(const tasvir_area_desc *d) { return d->h && (d->h->flags_ & TASVIR_AREA_FLAG_MAPPED_RW); }

bool tasvir_area_is_owner(const tasvir_area_desc *d, tasvir_thread *t) {
    if (!d)
        d = ttld.root_desc;
#ifdef TASVIR_DAEMON
    if (tasvir_is_booting()) {
        if (d == ttld.root_desc)
            return ttld.ndata->is_root;
        else if (d == ttld.node_desc)
            return true;
    }
#endif
    assert(d->owner || (d->type == TASVIR_AREA_TYPE_NODE));
    return d->owner == t;
}

void tasvir_area_normalize_name(const char *name, char *buf, size_t buf_size) {
    // prepend / if one is not present
    buf[0] = '/';
    strncpy(buf + 1, name + (name[0] == '/'), buf_size - 1);
}

#ifdef TASVIR_DAEMON
size_t tasvir_area_walk(tasvir_area_desc *d, tasvir_fnptr_walkcb fnptr) {
    if (!tasvir_area_is_active_local(d))
        return 0;
    size_t retval = 0;
    retval += fnptr(d);
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        for (size_t i = 0; i < d->h->nr_areas; i++) {
            retval += tasvir_area_walk(&d->h->child[i], fnptr);
        }
    }
    return retval;
}
#endif

void tasvir_update_va(const tasvir_area_desc *d, bool is_rw) {
    if (tasvir_area_is_mapped_rw(d) == is_rw)
        return;
    size_t len = d->len_logged;
    size_t offset = (uintptr_t)d->h - TASVIR_ADDR_BASE + is_rw * TASVIR_SIZE_DATA;
    void *ret = mmap(d->h, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttld.fd, offset);
    if (ret != d->h) {
        LOG_ERR("mmap for data area failed (request=%p return=%p). aborting...", (void *)d->h, ret);
        abort();
    }
    if (is_rw)
        d->h->flags_ |= TASVIR_AREA_FLAG_MAPPED_RW;

    LOG_INFO("name=%s mapping=%s", d->name, is_rw ? "rw" : "ro");
}

tasvir_area_desc *tasvir_new_alloc_desc(tasvir_area_desc desc) {
    tasvir_area_desc *d = NULL;
    void *h = NULL;

    if (!tasvir_area_is_owner(desc.pd, ttld.thread)) {
        if (tasvir_rpc_wait(S2US, (void **)&d, desc.pd, (tasvir_fnptr)&tasvir_new_alloc_desc, desc))
            return NULL;
        return d;
    }

    /* allocate descriptor and header */
    if (!strcmp(desc.name, "/")) { /* root area */
        d = ttld.root_desc;
        h = ttld.root_desc->h;
    } else {
        /* ensure area does not exist */
        for (size_t i = 0; i < desc.pd->h->nr_areas; i++) {
            if (!strncmp(desc.pd->h->child[i].name, desc.name, sizeof(tasvir_str))) {
                d = &desc.pd->h->child[i];
                h = d->h;
                if (d->owner != desc.owner) {
                    LOG_ERR("area %s already exists", desc.name);
                    return NULL;
                }
            }
        }
    }
    if (!d) {
        /* ensure enough descriptors */
        size_t *nr_areas = &desc.pd->h->nr_areas;
        if (*nr_areas >= TASVIR_NR_AREAS) {
            LOG_ERR("out of descriptors");
            return NULL;
        }
        d = &desc.pd->h->child[*nr_areas];
        h = (void *)TASVIR_ALIGN(
            (*nr_areas ? (uint8_t *)desc.pd->h->child[*nr_areas - 1].h + desc.pd->h->child[*nr_areas - 1].len
                       : (uint8_t *)&desc.pd->h->child[TASVIR_NR_AREAS]));
        if ((uint8_t *)h + desc.len >= (uint8_t *)desc.pd->h->diff_log[0].data) {
            LOG_ERR("d=%s out of space", desc.pd->name);
            return NULL;
        }
        tasvir_log(nr_areas, sizeof(desc.pd->h->nr_areas));
        (*nr_areas)++;
    }

    tasvir_log(d, sizeof(tasvir_area_desc));
    desc.h = h;
    if (ttld.node_desc && desc.type == TASVIR_AREA_TYPE_NODE)
        desc.sync_ext_us = ttld.node_desc->sync_ext_us;
    memcpy(d, &desc, sizeof(tasvir_area_desc));

    LOG_DBG("d=%s addr=%p", d->name, (void *)d);
    return d;
}

// FIXME: change args
tasvir_area_desc *tasvir_new(tasvir_area_desc desc) {
    if (desc.sync_int_us == 0)
        desc.sync_int_us = TASVIR_SYNC_INTERNAL_US;
    if (desc.sync_ext_us == 0)
        desc.sync_ext_us = TASVIR_SYNC_EXTERNAL_US;
    if (desc.type == 0)
        desc.type = TASVIR_AREA_TYPE_APP;
    desc.owner = ttld.thread;

#ifndef TASVIR_DAEMON
    if (!ttld.node) {
        LOG_ERR("initialize Tasvir first");
        return NULL;
    }
#endif
    if (!desc.pd)
        desc.pd = ttld.root_desc;

    /* calculate space requirements */
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;
    size_t size_metadata = offsetof(tasvir_area_header, child[is_container * TASVIR_NR_AREAS]);
    desc.len_logged = TASVIR_ALIGN(size_metadata + !is_container * desc.len);
    size_t offset_log = TASVIR_ALIGN(size_metadata + desc.len);
    size_t size_log = TASVIR_ALIGNX(desc.len_logged >> TASVIR_SHIFT_BYTE, sizeof(tasvir_log_t));
    desc.len = offset_log + TASVIR_ALIGN(TASVIR_NR_AREA_LOGS * size_log);

    /* allocate descriptor: may be a local or a remote request */
    tasvir_area_desc *d = tasvir_new_alloc_desc(desc);
    if (!d) {
        LOG_ERR("failed to allocate descriptor");
        return NULL;
    }

#ifdef TASVIR_DAEMON
    /* FIXME: hack for torn writes during boot */
    if (tasvir_is_booting()) {
        uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(S2US);
        bool success = false;
        while (__rdtsc() < end_tsc) {
            if ((success = (d->h && (!d->owner || d->owner->state == TASVIR_THREAD_STATE_RUNNING))))
                break;
            tasvir_service();
        }
        if (!d->h) {
            LOG_ERR("descriptor allocated but bootstrap data not received");
            return NULL;
        }
    }
#endif

    /* initialize the header */
    tasvir_area_header *h_ro = tasvir_data2ro(d->h);
    tasvir_area_header *h_rw = tasvir_data2rw(d->h);
    memset(h_rw, 0, size_metadata);
    memset(h_ro, 0, size_metadata);

    tasvir_update_owner(d, desc.owner);
    tasvir_area_header *h = d->h;
    /* exclude the private part of header from log/sync since it is local */
    tasvir_log(&h->d, sizeof(tasvir_area_header) - offsetof(tasvir_area_header, d));

    h->len_dalloc = size_metadata;

    h->flags_ |= TASVIR_AREA_FLAG_ACTIVE;
    h->last_sync_ext_us_ = 0;
    h->arena_ind_ = -1;
    h->d = d;
    h->version = 1;
    h->time_us = tasvir_time_us();
    h->nr_areas = 0;
    h->nr_users = 0;
    for (size_t i = 0; i < TASVIR_NR_AREA_LOGS; i++) {
        h->diff_log[i].version_start = 0;
        h->diff_log[i].version_end = 0;
        h->diff_log[i].start_us = h->time_us;
        h->diff_log[i].end_us = 0;
        h->diff_log[i].data = (tasvir_log_t *)((uint8_t *)h + offset_log + i * size_log);
    }
    if (ttld.node && tasvir_area_add_user(d, ttld.node, -1)) {
        LOG_ERR("failed to add local node as a subscriber of d=%s", d->name);
        return NULL;
    }

    char area_str[256];
    tasvir_area_str(d, area_str, sizeof(area_str));
    LOG_INFO("%s", area_str);

    return d;
}

/* TODO */
int tasvir_delete(tasvir_area_desc *d) {
    LOG_ERR("delete not implemented. aborting...")
    abort();
    (void)d;

    return 0;
}

int tasvir_area_add_user(tasvir_area_desc *d, tasvir_node *node, int idx) {
    assert(node || d == ttld.root_desc);
#ifndef TASVIR_DAEMON
    if (tasvir_area_is_local(d) && !tasvir_area_is_active(d))
        return -1;
#endif
    if (tasvir_area_is_attached(d, node))
        return 0;
    int retval = -1;
    char node_str[256] = {'\0'};
    bool is_req_local = node && ttld.node == node;

    if (node)
        tasvir_nid_str(&node->nid, node_str, sizeof(node_str));

    if (is_req_local) {
#ifdef TASVIR_DAEMON
        /* update the local list of areas and their versions maintained in tasvir_node */
        idx = -1;
        if (ttld.node->nr_areas + 1 > TASVIR_NR_AREAS) {
            LOG_ERR("insufficient space to add d=%s to the list of areas of the local node", d->name);
            return -1;
        }
        tasvir_log(&ttld.node->nr_areas, sizeof(ttld.node->nr_areas));
        for (size_t i = 0; i < ttld.node->nr_areas + 1; i++) {
            if (!ttld.node->areas_d[i]) {
                ttld.node->nr_areas++;
                tasvir_log(&ttld.node->areas_d[i], sizeof(ttld.node->areas_d[i]));
                tasvir_log(&ttld.node->areas_v[i], sizeof(ttld.node->areas_v[i]));
                ttld.node->areas_d[i] = d;
                ttld.node->areas_v[i] = 0;
                idx = i;
                LOG_INFO("d=%s local_idx=%lu nr_areas=%lu", d->name, i, ttld.node->nr_areas);
                break;
            } else if (ttld.node->areas_d[i] == d) {
                idx = i;
                break;
            }
        }
        /* remote rpc is initiated through the daemon */
        if (!tasvir_area_is_local(d)) {
            if (tasvir_rpc_wait(S2US, (void **)&retval, d, (tasvir_fnptr)&tasvir_area_add_user, d, node, idx))
                return -1;
            // trigger another version update: if we are in an rpc context here the caller is waiting on a new version
            // which otherwise wouldn't arrive
            tasvir_log(&ttld.node->nr_areas, sizeof(ttld.node->nr_areas));
            return retval;
        }
#else
        /* rpc to the local daemon which updates local subscriptions */
        if (tasvir_rpc_wait(S2US, (void **)&retval, ttld.node_desc, (tasvir_fnptr)&tasvir_area_add_user, d, node, -1) ||
            retval)
            return -1;
#endif
    }

    if (tasvir_area_is_owner(d, ttld.thread)) {
#ifndef TASVIR_DAEMON
        if (is_req_local) {
            for (size_t i = 0; i < ttld.node->nr_areas; i++) {
                if (node->areas_d[i] == d) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1) {
                LOG_ERR("invalid node-local subscription for d=%s node=%s", d->name, node_str);
                return -1;
            }
        }
#endif
        if (d->h->nr_users + 1 > TASVIR_NR_NODES) {
            LOG_ERR("insufficient space to add node to the list of nodes in d=%s", d->name);
            return -1;
        }

        /* log a write to trigger a version change for rpc */
        tasvir_log(&d->h->nr_users, sizeof(d->h->nr_users));
        if (node) {
            d->h->nr_users++;
            for (size_t i = 0; i < d->h->nr_users; i++) {
                if (!d->h->users[i].node) {
                    tasvir_log(&d->h->users[i], sizeof(d->h->users[i]));
                    d->h->users[i].node = node;
                    d->h->users[i].version = &node->areas_v[idx];
                    LOG_INFO("d=%s node=%s user_idx=%lu nr_users=%lu", d->name, node_str, i, d->h->nr_users);
                    break;
                }
            }
        }
#ifdef TASVIR_DAEMON
        if (d == ttld.root_desc)
            ttld.ndata->node_init_req = true;
#endif
    }

    return 0;
}

int tasvir_area_add_user_wait(uint64_t timeout_us, tasvir_area_desc *d, tasvir_node *node, int idx) {
    int retval = -1;
    uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(timeout_us);
    while (__rdtsc() < end_tsc && (retval = tasvir_area_add_user(d, node, idx))) {
        for (int i = 0; i < 1000; i++) {
            tasvir_service();
            rte_delay_us_block(1);
        }
    }
    return retval;
}

tasvir_area_desc *tasvir_attach(const char *name) {
    tasvir_area_desc *d = NULL;
    tasvir_area_desc *pd = NULL;

    /* find the area descriptor */
    char name_[256];
    tasvir_area_normalize_name(name, name_, sizeof(name_));
    char *tok = strtok(name_, "/");
    if (tok) {
        pd = ttld.root_desc;
    } else {
        tok = "/";
    }

    bool is_attached = false;
    do {
        d = tasvir_area_get_by_name(pd, tok);
        if (!d) /* invalid descriptor */
            return NULL;
        is_attached = tasvir_area_is_attached(d, ttld.node);
        if (!is_attached && tasvir_area_add_user(d, ttld.node, -1))
            return NULL;
        pd = d;
    } while ((tok = strtok(NULL, "/")));

    if (!is_attached) {
        char area_str[256];
        tasvir_area_str(d, area_str, sizeof(area_str));
        LOG_INFO("%s", area_str);
    }
    return d;
}

tasvir_area_desc *tasvir_attach_wait(uint64_t timeout_us, const char *name) {
    tasvir_area_desc *d;
    uint64_t end_tsc = __rdtsc() + tasvir_usec2tsc(timeout_us);
    while (__rdtsc() < end_tsc && !(d = tasvir_attach(name))) {
        for (int i = 0; i < 1000; i++) {
            tasvir_service();
            rte_delay_us_block(1);
        }
    }
    return d;
}

int tasvir_detach(tasvir_area_desc *d) {
    (void)d;
    LOG_ERR("detach not implemented. aborting...")
    abort();
    /* TODO: sanity check */
    /* TODO: update subscriber's list */

    return 0;
}

int tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    // FIXME: serialize request for ownership
    // on old owner: stop writing
    // on parent: change owner
    // on new owner: wait for old owner version
    // on old owner crash: wait for latest version

    assert(d && ttld.thread && owner);
    bool is_parent_owner = ttld.thread == d->pd->owner
#ifdef TASVIR_DAEMON
                           || (tasvir_is_booting() && ttld.ndata->is_root)
#endif
        ;

    if (is_parent_owner) {
        tasvir_log(&d->owner, sizeof(d->owner));
        d->owner = owner;
    } else if (d->owner != owner) {
        tasvir_rpc_wait(500 * MS2US, NULL, d->pd, (tasvir_fnptr)&tasvir_update_owner, d, owner);
    }

    if (ttld.thread == owner && d->owner == owner) {
        tasvir_area_header *h_rw = tasvir_data2rw(d->h);
        tasvir_area_header *h_ro = tasvir_data2ro(d->h);
        h_rw->flags_ |= TASVIR_AREA_FLAG_LOCAL;
        h_ro->flags_ |= TASVIR_AREA_FLAG_LOCAL;
        tasvir_update_va(d, true);
    }

    return d->owner == owner ? 0 : -1;
}

int tasvir_area_enable_dynamic_allocation(tasvir_area_desc *d, bool replace_malloc, bool disable_tcache) {
    d->h->flags_ |= TASVIR_AREA_FLAG_DYNAMIC;
    tasvir_extent_hooks_t *hooks = (tasvir_extent_hooks_t *)d->h->extent_hooks_;
    if (!d->h->extent_hooks_) {
        hooks = &ttld.extent_hooks[ttld.nr_extent_hooks++];
        memset(hooks, 0, sizeof(tasvir_extent_hooks_t));
        hooks->hooks.alloc = &tasvir_extent_alloc_hook;
        // hooks->hooks.dalloc = &tasvir_extent_dalloc_hook;
        hooks->hooks.merge = &tasvir_extent_merge_hook;
        hooks->hooks.split = &tasvir_extent_split_hook;
        hooks->d = d;
        d->h->extent_hooks_ = hooks;
        /* create a jemalloc arena with custom extent hooks */
        int rc;
        size_t sz = sizeof(unsigned);
        if ((rc = mallctl("arenas.create", (void *)&d->h->arena_ind_, &sz, (void *)&hooks,
                          sizeof(tasvir_extent_hooks_t *)))) {
            LOG_ERR("failed to create jemalloc arena backed by d=%s rc=%d", d->name, rc);
            return -1;
        }
    }

    /* change the default arena for the calling thread */
    unsigned arena_ind = replace_malloc ? d->h->arena_ind_ : 0;
    if (mallctl("thread.arena", NULL, NULL, (void *)&arena_ind, sizeof(unsigned))) {
        LOG_ERR("jemalloc thread.arena failed");
        return -1;
    }
    if (mallctl("thread.tcache.flush", NULL, NULL, NULL, 0)) {
        LOG_ERR("jemalloc thread.tcache.flush failed");
        return -1;
    }

    /* disable tcache when taking over malloc to ensure all allocations are served from the arena */
    bool enable_tcache = !disable_tcache;
    if (mallctl("thread.tcache.enabled", NULL, NULL, (void *)&enable_tcache, sizeof(bool))) {
        LOG_ERR("jemalloc thread.tcache.enabled %s failed", enable_tcache ? "set" : "unset");
        return -1;
    }

    return 0;
}
