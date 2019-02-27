#include "tasvir.h"

/* area management */

static const char *tasvir_area_type_str[] = {"invalid", "contianer", "node", "app"};

static inline bool tasvir_is_attached(const tasvir_area_desc *d, const tasvir_node *node) {
    if (d->h && d->h->active) {
        if (!node)
            return true;
        for (size_t i = 0; i < d->h->nr_users; i++)
            if (d->h->users[i].node == node)
                return true;
    }
    return false;
}

static inline bool tasvir_area_is_owned(const tasvir_area_desc *d) {
    if (!d) { /* assume called on root's pd */
        return ttld.is_root;
    } else if (!d->pd) { /* root area */
        return ttld.is_root;
    } else if (!ttld.thread) { /* preboot: node area, only daemon should ever reach here */
#ifdef TASVIR_DAEMON
        return true;
#else
        return false;
#endif
    } else if (!d->owner) { /* FIXME: am I missing a corner case? */
        return false;
    } else {
        return d->owner == ttld.thread;
    }
}

/* assumption: d && d->h */
static inline void tasvir_update_va(const tasvir_area_desc *d, bool is_rw) {
    void *ret;
    void *data = (uint8_t *)d->h;
    void *shadow = tasvir_data2shadow(d->h);
    ptrdiff_t data_offset = (uint8_t *)data - (uint8_t *)TASVIR_ADDR_BASE;
    ptrdiff_t shadow_offset = (uint8_t *)shadow - (uint8_t *)TASVIR_ADDR_BASE;
    ret = mmap(data, d->offset_log_end, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttld.fd,
               is_rw ? shadow_offset : data_offset);
    if (ret != data) {
        LOG_ERR("mmap for working area failed (request=%p return=%p)", data, ret);
        abort();
    }
    ret = mmap(shadow, d->offset_log_end, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttld.fd,
               is_rw ? data_offset : shadow_offset);
    if (ret != shadow) {
        LOG_ERR("mmap for scratch area failed (request=%p return=%p)", shadow, ret);
        abort();
    }

    /* FIXME: not the best place to update these tags */
    d->h->private_tag.rw = is_rw;
    ((tasvir_area_header *)shadow)->private_tag.rw = !is_rw;
}


tasvir_area_desc *tasvir_new(tasvir_area_desc desc) {
    if (!desc.owner && desc.type != TASVIR_AREA_TYPE_NODE)
        desc.owner = ttld.thread;
    if (desc.sync_int_us == 0)
        desc.sync_int_us = TASVIR_SYNC_INTERNAL_US;
    if (desc.sync_ext_us == 0)
        desc.sync_ext_us = TASVIR_SYNC_EXTERNAL_US;
    if (desc.type == 0)
        desc.type = TASVIR_AREA_TYPE_APP;

    desc.active = false;
    tasvir_area_desc *d = NULL;
    tasvir_area_desc *c = NULL;
    uint64_t time_us = tasvir_gettime_us();
    bool is_root_area = !desc.pd;
    bool is_desc_owner = tasvir_area_is_owned(desc.pd);
    bool is_owned = desc.type == TASVIR_AREA_TYPE_NODE ? !ttld.node : tasvir_area_is_owned(&desc);
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;

    if ((is_container && desc.nr_areas_max == 0) || (!is_container && desc.nr_areas_max != 0)) {
        LOG_ERR("mismatch between type and number of subareas (type=%s,nr_areas_max=%lu)",
                tasvir_area_type_str[desc.type], desc.nr_areas_max);
        return NULL;
    }
    if ((is_root_area && !is_container) || (!is_root_area && desc.pd->type != TASVIR_AREA_TYPE_CONTAINER)) {
        LOG_ERR("incorrect area type");
        return NULL;
    }

    size_t size_metadata = sizeof(tasvir_area_header) + desc.nr_areas_max * sizeof(tasvir_area_desc);
    if (is_owned)
        desc.offset_log_end = TASVIR_ALIGN(size_metadata + !is_container * desc.len);
    size_t offset_log = TASVIR_ALIGN(size_metadata + desc.len);
    size_t size_log = TASVIR_ALIGNX(desc.offset_log_end >> TASVIR_SHIFT_BYTE, sizeof(tasvir_log_t));
    if (is_owned)
        desc.len = offset_log + TASVIR_ALIGN(TASVIR_NR_AREA_LOGS * size_log);

    assert(is_root_area || desc.pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(!is_root_area || is_container);

    /* initialize the area descriptor */
    if (is_desc_owner) {
        void *h = NULL;
        if (is_root_area) {
            d = ttld.root_desc;
            h = (void *)TASVIR_ADDR_DATA;
        } else {
            c = tasvir_data(desc.pd);

            /* ensure enough descriptors */
            if (desc.pd->h->nr_areas >= desc.pd->nr_areas_max) {
                LOG_ERR("out of descriptors");
                return NULL;
            }

            /* ensure area does not exist */
            for (size_t i = 0; i < desc.pd->h->nr_areas; i++) {
                if (strncmp(c[i].name, desc.name, sizeof(tasvir_str)) == 0) {
                    LOG_ERR("area exists");
                    return NULL;
                }
            }

            size_t *nr_areas = &desc.pd->h->nr_areas;
            d = &c[*nr_areas];
            h = (void *)TASVIR_ALIGN((*nr_areas > 0 ? (uint8_t *)c[*nr_areas - 1].h + c[*nr_areas - 1].len
                                                    : (uint8_t *)c + desc.pd->nr_areas_max * sizeof(tasvir_area_desc)));
            if ((uint8_t *)h + desc.len >= (uint8_t *)desc.pd->h->diff_log[0].data) {
                LOG_ERR("out of space");
                return NULL;
            }
            (*nr_areas)++;
            tasvir_log(nr_areas, sizeof(*nr_areas));
        }
        memcpy(d, &desc, sizeof(tasvir_area_desc));
        d->h = h;
        if (d->boot_us == 0)
            d->boot_us = time_us;
        d->active = true;
        tasvir_log(d, sizeof(tasvir_area_desc));
    } else if (tasvir_rpc_wait(5 * S2US, (void **)&d, desc.pd, (tasvir_fnptr)&tasvir_new, desc) != 0)
        return NULL;

    /* sanity check */
    if (!d || !d->active || !d->h) {
        LOG_ERR("invalid descriptor: d=%p, d->active=%d, d->h=%p", (void *)d, d ? d->active : false,
                d ? (void *)d->h : NULL);
        return NULL;
    }

    /* initialize the header */
    if (is_owned) {
        tasvir_update_va(d, true);
        memset(d->h, 0, size_metadata);
        d->h->private_tag.rw = true;
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = true;
        d->h->private_tag.external_sync_pending = false;
        d->h->d = d;
        d->h->version = 1;
        d->h->time_us = time_us;
        d->h->nr_areas = 0;
        d->h->nr_users = 1;
        d->h->users[0].node = ttld.node;
        d->h->users[0].version = 0;
        for (size_t i = 0; i < TASVIR_NR_AREA_LOGS; i++) {
            tasvir_area_log *log = &d->h->diff_log[i];
            log->version_start = 0;
            log->version_end = 0;
            log->start_us = time_us;
            log->end_us = 0;
            log->data = (tasvir_log_t *)((uint8_t *)d->h + offset_log + i * size_log);
        }
        d->h->active = true;
        tasvir_log(&d->h->d, sizeof(tasvir_area_header) - offsetof(tasvir_area_header, d));
    }

    LOG_INFO(
        "name=%s type=%s len=0x%lx sync_us=%lu/%lu boot_us=%lu nr_areas_max=%lu active=%s "
        "d=%p pd=%p owner=%p h=%p is_desc_owner=%s is_owned=%s is_local=%s",
        d->name, tasvir_area_type_str[d->type], d->len, d->sync_int_us, d->sync_ext_us, d->boot_us, d->nr_areas_max,
        d->active ? "true" : "false", (void *)d, (void *)d->pd, (void *)d->owner, (void *)d->h,
        is_desc_owner ? "true" : "false", is_owned ? "true" : "false", d->h->private_tag.local ? "true" : "false");

    return d;
}

/* asssumption: d && d->pd */
int tasvir_delete(tasvir_area_desc *d) {
    /* TODO: remove from d->pd */
    if (!tasvir_area_is_owned(d->pd)) {
        int retval = -1;
        if (tasvir_rpc_wait(S2US, (void **)&retval, d->pd, (tasvir_fnptr)&tasvir_delete, d) != 0) {
            return -1;
        }
        return retval;
    }

    d->active = false;
    return 0;
}

int tasvir_attach_helper(tasvir_area_desc *d, tasvir_node *node) {
    if (tasvir_is_attached(d, node))
        return 0;

    if (tasvir_area_is_owned(d)) {
        if (d->h->nr_users >= TASVIR_NR_NODES_AREA) {
            LOG_ERR("%s has reached max number of subscribers", d->name);
            return -1;
        }

        if (node) {
            d->h->users[d->h->nr_users].node = node;
            d->h->users[d->h->nr_users].version = 0;
            d->h->nr_users++;
            tasvir_log(&d->h->nr_users, sizeof(d->h->nr_users));
            tasvir_log(&d->h->users[d->h->nr_users], sizeof(d->h->users[d->h->nr_users]));
        }

#ifdef TASVIR_DAEMON
        tasvir_sync_external_area(d, true);
#else
        abort();
        /*
        tasvir_rpc_status *rs = tasvir_rpc(ttld.node_desc, (tasvir_fnptr)&tasvir_sync_external_area, d, true);
        if (rs)
            rs->do_free = true;
        */
#endif

#ifdef TASVIR_DAEMON
        /* FIXME: hack to distribute node and thread info at boot time */
        if (d == ttld.root_desc) {
            tasvir_area_desc *c = tasvir_data(d);
            for (size_t i = 0; i < d->h->nr_areas; i++)
                if (c[i].type == TASVIR_AREA_TYPE_NODE)
                    tasvir_sync_external_area(&c[i], true);
        }
#endif
    } else if (d->owner && (d == ttld.root_desc || ttld.thread) &&
               tasvir_rpc_wait(S2US, NULL, d, (tasvir_fnptr)&tasvir_attach_helper, d, node) != 0) {
        return -1;
    }

    if (d == ttld.root_desc && !node)
        return 0;
    return !tasvir_is_attached(d, node);
}

/* TODO: sanity checking? */
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer) {
    tasvir_area_desc *d = NULL;

    if (!pd) { /* root_area */
        if (strncmp(ttld.root_desc->name, name, sizeof(tasvir_str)) == 0) {
            d = ttld.root_desc;
        } else {
            LOG_ERR("name does not match root area's name");
        }
    } else if (pd->active && pd->type == TASVIR_AREA_TYPE_CONTAINER && pd->h && pd->h->active) {
        tasvir_area_desc *c = tasvir_data(pd);
        for (size_t i = 0; i < pd->h->nr_areas; i++) {
            if (strncmp(c[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &c[i];
                break;
            }
        }
    }

    if (!tasvir_area_is_valid(d))
        return NULL;

    if ((!d->h->active || d == ttld.root_desc) && !tasvir_area_is_local(d)) {
        if (tasvir_attach_helper(d, node ? node : ttld.node))
            return NULL;
    }

    if (!d->h->active)
        return NULL;

    tasvir_update_va(d, writer);
    LOG_INFO("name=%s len=%lu h=%p", d->name, d->len, (void *)d->h);
    return d;
}

tasvir_area_desc *tasvir_attach_wait(tasvir_area_desc *pd, const char *name, tasvir_node *node, bool writer,
                                     uint64_t timeout_us) {
    tasvir_area_desc *d;
    uint64_t end_tsc = tasvir_rdtsc() + tasvir_usec2tsc(timeout_us);
    while (tasvir_rdtsc() < end_tsc && !(d = tasvir_attach(pd, name, node, writer))) {
        for (int i = 0; i < 1000; i++) {
            tasvir_service();
            rte_delay_us_block(1);
        }
    }
    return d;
}

int tasvir_detach(tasvir_area_desc *d) {
    (void)d;
    /* TODO: sanity check */
    /* TODO: update subscriber's list */

    return 0;
}

int tasvir_update_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    tasvir_thread *desc_owner = d->pd ? d->pd->owner : d->owner;
    bool is_new_owner = owner == ttld.thread;
    bool is_old_owner = d->owner == ttld.thread;
    bool is_desc_owner = desc_owner == ttld.thread;

    if (is_new_owner) {
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = true;
        tasvir_update_va(d, true);
        /* FIXME: error reporting and function return value */
        /* FIXME: change to async and wait for change to propagate */

        if (!is_old_owner) {
            /* rpc to previous owner if one exists */
            if (d->owner && tasvir_rpc_wait(S2US, NULL, d, (tasvir_fnptr)&tasvir_update_owner, d, owner) != 0)
                return -1;

            /* rpc to desc owner if not the same as desc owner (previous call) */
            if (d->pd && !is_desc_owner &&
                tasvir_rpc_wait(S2US, NULL, d->pd, (tasvir_fnptr)&tasvir_update_owner, d, owner) != 0)
                return -1;
        }
    } else if (is_old_owner) {
        d->h->private_tag.local = ((tasvir_area_header *)tasvir_data2shadow(d->h))->private_tag.local = false;
        /* restore the mappings of the old owner */
        tasvir_update_va(d, false);
    }

    if (is_desc_owner) {
        d->owner = owner;
        tasvir_log(&d->owner, sizeof(d->owner));
    }

    return 0;
}
