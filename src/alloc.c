#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "tasvir.h"

void *tasvir_extent_alloc_hook(extent_hooks_t *extent_hooks, void *new_addr, size_t size, size_t alignment, bool *zero,
                               bool *commit, unsigned arena_ind) {
    // do not support placement
    if (new_addr)
        return NULL;
    tasvir_extent_hooks_t *hooks = (tasvir_extent_hooks_t *)extent_hooks;
    tasvir_area_header *h = hooks->d->h;
    void *alloc_head = (void *)TASVIR_ALIGNX((uintptr_t)h + h->len_dalloc, alignment);
    size_t len_dalloc = (uintptr_t)alloc_head - (uintptr_t)h + size;
    if (len_dalloc > hooks->d->len_logged) {
        LOG_ERR("OOM arena=%d addr=%p size=%lu", arena_ind, alloc_head, size);
        return NULL;
    }
    tasvir_log(&h->len_dalloc, sizeof(h->len_dalloc));
    h->len_dalloc = len_dalloc;

    if (*zero)
        memset(alloc_head, 0, size);

    *commit = true;
    LOG_DBG("arena=%d addr=%p size=%lu alignment=%lu zero=%d commit=%d new_tail=%p", arena_ind, alloc_head, size,
            alignment, *zero, *commit, (void *)((uintptr_t)h + h->len_dalloc));
    return alloc_head;
}

bool tasvir_extent_dalloc_hook(extent_hooks_t *extent_hooks, void *addr, size_t size, bool committed,
                               unsigned arena_ind) {
    tasvir_extent_hooks_t *hooks = (tasvir_extent_hooks_t *)extent_hooks;
    tasvir_area_header *h = hooks->d->h;

    bool tail = (uintptr_t)addr + size == (uintptr_t)h + h->len_dalloc;
    if (tail) {
        tasvir_log(&h->len_dalloc, sizeof(h->len_dalloc));
        h->len_dalloc -= size;
    }
    LOG_DBG("arena=%d addr=%p size=%lu committed=%d success=%d", arena_ind, addr, size, committed, tail);
    return !tail;
}

bool tasvir_extent_merge_hook(UNUSED extent_hooks_t *extent_hooks, UNUSED void *addr_a, UNUSED size_t size_a,
                              UNUSED void *addr_b, UNUSED size_t size_b, UNUSED bool committed,
                              UNUSED unsigned arena_ind) {
    // LOG_DBG("arena=%d addr=%p/%p size=%lu/%lu committed=%d", arena_ind, addr_a, addr_b, size_a, size_b, committed);
    return false;
}

bool tasvir_extent_split_hook(UNUSED extent_hooks_t *extent_hooks, UNUSED void *addr, UNUSED size_t size,
                              UNUSED size_t size_a, UNUSED size_t size_b, UNUSED bool committed,
                              UNUSED unsigned arena_ind) {
    // LOG_DBG("arena=%d addr=%p size=%lu->%lu/%lu committed=%d", arena_ind, addr, size, size_a, size_b, committed);
    return false;
}
