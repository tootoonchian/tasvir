#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ring.h>

#include "tasvir.h"

static tasvir_tls_state ttls;  // tasvir thread-local state

#define TASVIR_LOG(...)                                                                     \
    {                                                                                       \
        fprintf(stderr, "%14lu %-22.22s ", ttls.local ? ttls.local->time_us : 0, __func__); \
        fprintf(stderr, __VA_ARGS__);                                                       \
    }

/* function prototypes and rpc methods */

static void tasvir_delete_rpc(void *ret, void **args) { *(int *)ret = tasvir_delete(*(tasvir_area_desc **)args[0]); }

static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type);
static void tasvir_init_thread_rpc(void *ret, void **args) {
    *(tasvir_thread **)ret = tasvir_init_thread(*(pid_t *)args[0], *(uint16_t *)args[1], *(uint8_t *)args[2]);
}

static inline void tasvir_init_finish(tasvir_thread *);
static void tasvir_init_finish_rpc(void *ret __attribute__((unused)), void **args) {
    tasvir_init_finish(*(tasvir_thread **)args[0]);
}
static void tasvir_new_rpc(void *ret, void **args) {
    *(tasvir_area_desc **)ret = tasvir_new(*(tasvir_area_desc *)args[0], *(uint64_t *)args[1], *(size_t *)args[2]);
}

void tasvir_set_owner_rpc(void *ret __attribute__((unused)), void **args) {
    tasvir_set_owner(*(tasvir_area_desc **)args[0], *(tasvir_thread **)args[1]);
}

/* utils */

static inline int tasvir_barrier_wait(atomic_uint *count, int64_t timeout_us) {
    unsigned int val = atomic_fetch_sub(count, 1) - 1;
    while (val > 0) {
        if (timeout_us-- > 0) {
            rte_delay_us_block(1);
        } else {
            if (atomic_compare_exchange_weak(count, &val, val + 1)) {
                return -1;
            }
        }
        val = atomic_load(count);
    }
    return 0;
}

static inline uint64_t tasvir_gettime_us() { return 1E6 * rte_rdtsc() / ttls.local->tsc_hz; }

static inline bool tasvir_is_thread_id_local(tasvir_thread_id *id) {
    return memcmp(&id->node_id, &ttls.node->id, sizeof(tasvir_node_id)) == 0;
}

static inline bool tasvir_is_thread_local(tasvir_thread *i) {
    return memcmp(&i->id.node_id, &ttls.node->id, sizeof(tasvir_node_id)) == 0;
}

static inline void tasvir_change_vaddr(void *addr1, void *addr2, size_t len, bool swap) {
    void *ret;
    ptrdiff_t addr1_rel = (uint8_t *)(swap ? addr2 : addr1) - (uint8_t *)TASVIR_ADDR_BASE;
    ptrdiff_t addr2_rel = (uint8_t *)(swap ? addr1 : addr2) - (uint8_t *)TASVIR_ADDR_BASE;
    ret = mmap(addr1, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttls.fd, addr1_rel);
    assert(ret == addr1);
    ret = mmap(addr2, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED | MAP_FIXED, ttls.fd, addr2_rel);
    assert(ret == addr2);
}

/* initializtion */

static inline void tasvir_init_rpc() {
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &tasvir_init_thread_rpc,
        .name = "tasvir_init_thread",
        .fid = 1,
        .argc = 3,
        .ret_len = sizeof(tasvir_thread *),
        .arg_lens = {sizeof(pid_t), sizeof(uint16_t), sizeof(uint8_t)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){.fnptr = &tasvir_new_rpc,
                                          .name = "tasvir_new",
                                          .fid = 2,
                                          .argc = 3,
                                          .ret_len = sizeof(tasvir_area_desc *),
                                          .arg_lens = {sizeof(tasvir_area_desc), sizeof(uint64_t), sizeof(size_t)}});
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &tasvir_delete_rpc,
        .name = "tasvir_delete",
        .fid = 3,
        .argc = 1,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &tasvir_init_finish_rpc,
        .name = "tasvir_init_finish",
        .fid = 4,
        .argc = 1,
        .ret_len = 0,
        .arg_lens = {sizeof(tasvir_thread *)},
    });
    tasvir_rpc_register(&(tasvir_fn_info){
        .fnptr = &tasvir_set_owner_rpc,
        .name = "tasvir_set_owner",
        .fid = 5,
        .argc = 2,
        .ret_len = 0,
        .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_thread *)},
    });
}

static inline int tasvir_init_dpdk(uint16_t core) {
    int argc = 0, retval;
    char *argv[64];
    char core_str[32], mem_str[32], base_virtaddr[32];
    snprintf(core_str, sizeof(core_str), "%d", core);
    snprintf(mem_str, sizeof(mem_str), "64");
    snprintf(base_virtaddr, sizeof(base_virtaddr), "%p", TASVIR_DPDK_ADDR_BASE);
    argv[argc++] = "tasvir";
    argv[argc++] = "--base-virtaddr";
    argv[argc++] = base_virtaddr;
    argv[argc++] = "-l";
    argv[argc++] = core_str;
    argv[argc++] = "-n";
    argv[argc++] = "4";
    argv[argc++] = "--file-prefix";
    argv[argc++] = "tasvir";
    argv[argc++] = "--log-level";
    argv[argc++] = "7";
    argv[argc++] = "--socket-mem";
    argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
    argv[argc++] = ttls.is_daemon ? "primary" : "secondary";
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        TASVIR_LOG("rte_eal_init failed\n");
        return -1;
    }
    return 0;
}

static int tasvir_init_local() {
    void *addr;
    int shm_oflag = ttls.is_daemon ? O_CREAT | O_EXCL | O_RDWR : O_RDWR;
    mode_t shm_mode = ttls.is_daemon ? S_IRUSR | S_IWUSR : 0;

    ttls.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttls.fd == -1)
        return -1;
    if (ftruncate(ttls.fd, TASVIR_SIZE_WHOLE)) {
        TASVIR_LOG("ftruncate failed (%s)\n", strerror(errno));
        return -1;
    }
    ttls.fd_huge = open("/dev/hugepages/tasvir", O_CREAT | O_RDWR, 0600);
    if (ttls.fd_huge == -1)
        return -1;
    if (ftruncate(ttls.fd_huge, TASVIR_SIZE_LOG)) {
        TASVIR_LOG("ftruncate failed (%s)\n", strerror(errno));
        return -1;
    }
    addr = mmap(TASVIR_ADDR_BASE, TASVIR_SIZE_WHOLE, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttls.fd, 0);
    assert(addr == TASVIR_ADDR_BASE);
    /*addr = mmap(TASVIR_ADDR_LOG, TASVIR_SIZE_LOG, PROT_READ | PROT_WRITE,
                MAP_NORESERVE | MAP_SHARED | MAP_FIXED | MAP_HUGETLB, ttls.fd_huge, 0);
    assert(addr == TASVIR_ADDR_LOG);*/

    ttls.local = TASVIR_ADDR_BASE;

    if (ttls.is_daemon) {
        memset(ttls.local, 0, sizeof(tasvir_local));
        /* boot mutex */
        pthread_mutexattr_setpshared(&ttls.local->mutex_attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ttls.local->mutex_boot, &ttls.local->mutex_attr);

        /* mempool */
        ttls.local->mp =
            rte_pktmbuf_pool_create("mempool", 16 * 1024, 256, 0, 2048 + RTE_PKTMBUF_HEADROOM, rte_socket_id());

        /* timing */
        ttls.local->tsc_hz = rte_get_tsc_hz();

        ttls.local->dstate.last_stat = 0;
        ttls.local->dstate.sync_count = 0;
        ttls.local->dstate.sync_cumtime_us = 0;
        ttls.local->dstate.sync_cumbytes = 0;
    }

    return 0;
}

static int tasvir_init_root() {
    tasvir_area_desc *d_ret;
    ttls.root_desc = (tasvir_area_desc *)TASVIR_ADDR_ROOT_DESC;

    if (ttls.is_root) {
        d_ret = tasvir_new((tasvir_area_desc){.pd = NULL,
                                              .owner = NULL,
                                              .type = TASVIR_AREA_TYPE_CONTAINER,
                                              .name = "root",
                                              .len = TASVIR_SIZE_GLOBAL},
                           5000, TASVIR_SIZE_ROOT_CONTAINER);
        assert(d_ret == ttls.root_desc);
    } else {
        d_ret = tasvir_attach(NULL, "root");
        assert(d_ret == ttls.root_desc);
    }

    return 0;
}

static int tasvir_init_node() {
    // FIXME: assuming a clean boot
    if (ttls.is_daemon) {
        /* id and address */
        ttls.node_desc = tasvir_new((tasvir_area_desc){.pd = ttls.root_desc,
                                                       .owner = NULL,
                                                       .type = TASVIR_AREA_TYPE_NODE,
                                                       .name = "node-68:05:ca:27:99:48",
                                                       .len = sizeof(tasvir_node)},
                                    50000, 0);
        ttls.node = (tasvir_node *)ttls.node_desc->h->data;
        memset(ttls.node, 0, sizeof(tasvir_node));
        sscanf("68:05:ca:27:99:48", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ttls.node->id.ethaddr[0],
               &ttls.node->id.ethaddr[1], &ttls.node->id.ethaddr[2], &ttls.node->id.ethaddr[3],
               &ttls.node->id.ethaddr[4], &ttls.node->id.ethaddr[5]);
        ttls.node->heartbeat_us = TASVIR_HEARTBEAT_US;

        /* time */
        tasvir_log_write(ttls.node, sizeof(tasvir_node));
    } else {
        ttls.node_desc = tasvir_attach(ttls.root_desc, "node-68:05:ca:27:99:48");
        ttls.node = (tasvir_node *)ttls.node_desc->h->data;
        tasvir_local_istate *daemon_istate = &ttls.local->istate[TASVIR_THREAD_DAEMON_IDX];

        /* daemon alive? */
        uint64_t time_us = tasvir_gettime_us();
        if (!ttls.node_desc->active) {
            TASVIR_LOG("daemon is inactive\n");
            return -1;
        } else if (time_us > daemon_istate->update_us &&
                   time_us - daemon_istate->update_us > ttls.node_desc->h->stale_us) {
            TASVIR_LOG("daemon has been stale for %lu us (> %lu), last activity %lu\n",
                       time_us - ttls.node_desc->h->update_us, ttls.node_desc->h->stale_us,
                       ttls.node_desc->h->update_us);
            return -1;
        }
    }

    return 0;
}

static inline tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core, uint8_t type) {
    tasvir_str tmp;
    tasvir_thread *inst = NULL;
    uint16_t tid;

    if (!ttls.is_daemon) {
        // FIXME: robustness
        pthread_mutex_lock(&ttls.local->mutex_boot);
        inst = tasvir_rpc_sync(NULL, 10000, &tasvir_init_thread_rpc, pid, core, type);
        pthread_mutex_unlock(&ttls.local->mutex_boot);
        return inst;
    }

    // find thread id
    for (tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttls.node->threads[tid].status != TASVIR_THREAD_STATUS_RUNNING &&
            ttls.node->threads[tid].status != TASVIR_THREAD_STATUS_BOOTING)
            break;
    }

    if (tid == TASVIR_NR_THREADS_LOCAL)
        return inst;

    // populate thread
    inst = &ttls.node->threads[tid];
    inst->core = core;
    inst->type = type;
    inst->id.node_id = ttls.node->id;
    inst->id.idx = tid;
    inst->id.pid = pid;
    inst->status = TASVIR_THREAD_STATUS_BOOTING;
    TASVIR_LOG("tid=%d core=%d pid=%d\n", inst->id.idx, inst->core, inst->id.pid);
    tasvir_log_write(inst, sizeof(tasvir_thread));

    /* rings */
    sprintf(tmp, "tasvir_tx_%d", tid);
    ttls.local->istate[tid].ring_tx =
        rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
    sprintf(tmp, "tasvir_rx_%d", tid);
    ttls.local->istate[tid].ring_rx =
        rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
    ttls.local->istate[tid].nr_jobs = 0;

    return inst;
}

static inline void tasvir_kill_thread_ownership(tasvir_thread *inst, tasvir_area_desc *d) {
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_container *c = (tasvir_container *)d->h->data;
        for (size_t i = 0; i < c->nr_areas; i++)
            tasvir_kill_thread_ownership(inst, &c->descs[i]);
    }
    if (d->owner == inst)
        tasvir_set_owner(d, NULL);
}

static inline void tasvir_kill_thread(tasvir_thread *inst) {
    assert(ttls.is_daemon && tasvir_is_thread_local(inst));
    tasvir_local_istate *istate = &ttls.local->istate[inst->id.idx];
    TASVIR_LOG("thread=%d idle_time=%zd remaining_threads=%lu\n", inst->id.idx, ttls.local->time_us - istate->update_us,
               ttls.node->nr_threads - 1);
    istate->sync = false;
    istate->nr_jobs = 0;
    istate->update_us = 0;

    /* change ownership */
    tasvir_kill_thread_ownership(inst, ttls.root_desc);

    /* kill by pid */
    // kill(inst->id.pid, SIGKILL);

    ttls.node->nr_threads--;
    tasvir_log_write(&ttls.node->nr_threads, sizeof(ttls.node->nr_threads));
    inst->status = TASVIR_THREAD_STATUS_DEAD;
    tasvir_log_write(&inst->status, sizeof(inst->status));

    rte_ring_free(ttls.local->istate[inst->id.idx].ring_rx);
    rte_ring_free(ttls.local->istate[inst->id.idx].ring_tx);
}

static inline void tasvir_init_finish(tasvir_thread *inst) {
    assert(inst->status == TASVIR_THREAD_STATUS_BOOTING);
    if (ttls.is_daemon) {
        inst->status = TASVIR_THREAD_STATUS_RUNNING;
        tasvir_log_write(&inst->status, sizeof(inst->status));
        ttls.node->nr_threads++;
        tasvir_log_write(&ttls.node->nr_threads, sizeof(ttls.node->nr_threads));
        // backfill area owners
        ttls.node_desc->owner = ttls.thread;
        tasvir_log_write(&ttls.node_desc->owner, sizeof(tasvir_thread *));
        if (ttls.is_root) {
            ttls.root_desc->owner = ttls.thread;
            tasvir_log_write(&ttls.root_desc->owner, sizeof(tasvir_thread *));
        }
    } else {
        tasvir_rpc_sync(NULL, 10000, &tasvir_init_finish_rpc, inst);
    }

    TASVIR_LOG("tid=%d core=%d pid=%d\n", inst->id.idx, inst->core, inst->id.pid);
}

tasvir_area_desc *tasvir_init(uint16_t core, uint8_t type) {
    assert(!ttls.node && !ttls.thread);
    assert(sizeof(tasvir_local) <= TASVIR_SIZE_LOCAL_STRUCT);

    memset(&ttls, 0, sizeof(tasvir_tls_state));
    ttls.is_daemon = type == TASVIR_THREAD_TYPE_DAEMON || type == TASVIR_THREAD_TYPE_ROOT;
    ttls.is_root = type == TASVIR_THREAD_TYPE_ROOT;

    tasvir_init_rpc();

    if (tasvir_init_dpdk(core)) {
        TASVIR_LOG("tasvir_init_dpdk failed\n");
        return MAP_FAILED;
    }

    if (tasvir_init_local()) {
        TASVIR_LOG("tasvir_init_local failed\n");
        return MAP_FAILED;
    }
    if (tasvir_init_root()) {
        TASVIR_LOG("tasvir_init_root failed\n");
        return MAP_FAILED;
    }

    if (tasvir_init_node()) {
        TASVIR_LOG("tasvir_init_node failed\n");
        return MAP_FAILED;
    }

    ttls.thread = tasvir_init_thread(getpid(), core, type);
    if (!ttls.thread) {
        TASVIR_LOG("tasvir_init_thread failed\n");
        return MAP_FAILED;
    }

    tasvir_init_finish(ttls.thread);

    return ttls.root_desc;
}

/* area management */

tasvir_area_desc *tasvir_new(tasvir_area_desc desc, uint64_t stale_us, size_t container_len) {
    desc.len = TASVIR_ALIGN(sizeof(tasvir_area_header) + desc.len);
    desc.active = true;
    container_len = TASVIR_ALIGN(container_len);
    size_t i;

    if (!desc.owner)
        desc.owner = ttls.thread;

    uint64_t time_us = tasvir_gettime_us();
    void *addr = NULL;
    bool is_root_area = !desc.pd;
    bool is_desc_owner = is_root_area || (desc.pd->owner == ttls.thread);
    bool is_owner = !desc.owner || desc.owner == ttls.thread;
    bool is_container = desc.type == TASVIR_AREA_TYPE_CONTAINER;
    tasvir_area_desc *d = NULL;
    tasvir_container *c = NULL;

    assert(is_root_area || desc.pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(!is_root_area || is_container);
    assert(is_container || container_len == 0);

    // initialize area descriptor
    if (is_root_area) {
        d = ttls.root_desc;
        addr = TASVIR_ADDR_GLOBAL;
    } else if (is_desc_owner) {
        tasvir_container *c = (tasvir_container *)desc.pd->h->data;
        assert(sizeof(tasvir_container) + (c->nr_areas + 1) * sizeof(tasvir_area_desc) <= c->len);

        /* FIXME: use an allocator here */
        d = &c->descs[c->nr_areas];

        // area exists
        for (i = 0; i < c->nr_areas; i++) {
            if (strncmp(c->descs[i].name, desc.name, sizeof(tasvir_str)) == 0) {
                return NULL;
            }
        }

        if (c->nr_areas > 0) {
            addr = (tasvir_area_header *)((uint8_t *)c->descs[c->nr_areas - 1].h + c->descs[c->nr_areas - 1].len);
        } else {
            addr = (tasvir_area_header *)((uint8_t *)c->descs + c->len);
        }
        // FIXME: 512-bit each for a 64-bit cacheline
        addr = (void *)TASVIR_ALIGN(addr);
        assert((uint8_t *)addr + desc.len <= (uint8_t *)desc.pd->h + desc.pd->len);
        c->nr_areas++;
        tasvir_log_write(&c->nr_areas, sizeof(c->nr_areas));
    } else {
        d = tasvir_rpc_sync(NULL, 10000, &tasvir_new_rpc, desc, stale_us, container_len);
        if (d == NULL) {
            return MAP_FAILED;
        }
    }

    if (is_desc_owner) {
        rte_memcpy(d, &desc, sizeof(tasvir_area_desc));
        tasvir_log_write(d, sizeof(tasvir_area_desc));
        d->h = addr;
    }

    if (is_owner) {
        tasvir_set_owner(d, ttls.thread);
        d->h->d = d;
        d->h->version = 1;
        d->h->stale_us = stale_us;
        d->h->update_us = time_us;
        d->h->boot_us = time_us;
        if (is_container) {
            c = (tasvir_container *)&d->h->data;
            c->nr_areas = 0;
            c->len = container_len;
        }
        tasvir_log_write(d->h, sizeof(tasvir_area_header) + (is_container ? sizeof(tasvir_container) : 0));
    }

    TASVIR_LOG("is_desc_owner=%d pd=%p owner=%p type=%d name=%s len=%lu h=%p stale_us=%lu container_len=%lu\n",
               is_desc_owner, (void *)d->pd, (void *)d->owner, d->type, d->name, d->len, (void *)d->h, stale_us,
               container_len);

    return d;
}

int tasvir_delete(tasvir_area_desc *d) {
    assert(d->pd);
    bool is_local = d->pd->owner == ttls.thread;
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);

    // TODO: remove from d->pd
    if (is_local) {
        d->active = false;
    } else {
        return *(int *)tasvir_rpc_sync(NULL, 10000, &tasvir_delete_rpc, d);
    }
    return 0;
}

tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, char *name) {
    size_t i;
    tasvir_area_desc *d = NULL;
    tasvir_container *c;

    if (strncmp(name, "root", sizeof(tasvir_str)) == 0) {
        assert(!pd);
        d = ttls.root_desc;
    } else {
        assert(pd && pd->type == TASVIR_AREA_TYPE_CONTAINER);
        c = (tasvir_container *)pd->h->data;
        assert(sizeof(tasvir_container) + c->nr_areas * sizeof(tasvir_area_desc) <= c->len);
        for (i = 0; i < c->nr_areas; i++) {
            if (strncmp(c->descs[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &c->descs[i];
                break;
            }
        }
    }

    if (d == NULL) {
        TASVIR_LOG("could not find area %s under %s\n", name, pd->name);
        return MAP_FAILED;
    }
    // FIXME: update subscriber's list
    // FIXME: handle no local version

    TASVIR_LOG("name=%s len=%lu h=%p\n", name, d->len, (void *)d->h);

    return d;
}

int tasvir_detach(tasvir_area_desc *d) {
    assert(d->pd);
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);

    // FIXME: update subscriber's list

    return 0;
}

void tasvir_set_owner(tasvir_area_desc *d, tasvir_thread *owner) {
    tasvir_thread *desc_owner = d->pd ? d->pd->owner : d->owner;
    bool is_new_owner = owner == ttls.thread;
    bool is_old_owner = d->owner == ttls.thread;
    bool is_desc_owner = desc_owner == ttls.thread;
    void *addr, *addr_shadow;
    size_t len;

    addr = d->h;
    addr_shadow = tasvir_addr_shadow(addr);

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        len = sizeof(d->h) + ((tasvir_container *)d->h->data)->len;
    } else {
        len = d->len;
    }

    if (is_desc_owner) {
        d->owner = owner;
        tasvir_log_write(&d->owner, sizeof(d->owner));
    }

    // restore the mappings of the old owner
    if (is_new_owner) {
        tasvir_change_vaddr(addr, addr_shadow, len, true);

        // FIXME: change to async and wait for change to propagate
        if (d->owner && !is_old_owner) {
            // rpc to previous owner
            tasvir_rpc_sync(d->owner, 10000, &tasvir_set_owner_rpc, d, owner);
        }

        if (desc_owner && !is_desc_owner) {
            // rpc to desc owner
            tasvir_rpc_sync(d->pd->owner, 10000, &tasvir_set_owner_rpc, d, owner);
        }
    } else if (is_old_owner) {
        tasvir_change_vaddr(addr, addr_shadow, len, false);
    }
}

/* rpc */

static tasvir_rpc_status *tasvir_vrpc_async(tasvir_thread *inst, tasvir_fnptr fnptr, bool do_free, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *msg;
    tasvir_rpc_status *status;
    struct rte_ring *ring = ttls.local->istate[ttls.thread ? ttls.thread->id.idx : TASVIR_THREAD_DAEMON_IDX].ring_tx;
    if (rte_mempool_get(ttls.local->mp, (void **)&msg)) {
        TASVIR_LOG("rte_mempool_get failed\n");
        return NULL;
    }

    if (inst == NULL)
        inst = &ttls.node->threads[TASVIR_THREAD_DAEMON_IDX];

    tasvir_fn_info *fni;
    HASH_FIND(h_fnptr, ttls.ht_fnptr, &fnptr, sizeof(fnptr), fni);
    assert(fni);

    // FIXME: using daemon id as src during boot to simplify impl
    msg->h.src_id = ttls.thread ? ttls.thread->id : ttls.node->threads[TASVIR_THREAD_DAEMON_IDX].id;
    msg->h.dst_id = inst->id;
    msg->h.id = ttls.nr_msgs++;
    msg->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    msg->h.time_us = ttls.local->time_us;
    msg->fid = fni->fid;
    ptr = msg->data;

    for (i = 0; i < fni->argc; i++) {
        if (fni->arg_lens[i] <= sizeof(int)) {
            *(int *)ptr = va_arg(argp, int);
        } else {
            switch (fni->arg_lens[i]) {
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
                TASVIR_LOG("missing support for argument type len=%lu\n", fni->arg_lens[i]);
                abort();
                break;
            }
        }
        msg->arg_ptrs[i] = ptr;
        ptr += TASVIR_ALIGNX(fni->arg_lens[i], sizeof(int));
    }

    if (rte_ring_sp_enqueue(ring, msg) != 0) {
        TASVIR_LOG("rte_ring_sp_enqueue failed\n");
        rte_mempool_put(ttls.local->mp, (void *)msg);
        return NULL;
    }
    TASVIR_LOG("id=%d fid=%d name=%s argc=%d msg=%p\n", msg->h.id, msg->fid, fni->name, fni->argc, (void *)msg);

    status = &ttls.status_l[msg->h.id];
    // garbage collect a previous status
    if (status->do_free && status->response)
        rte_mempool_put(ttls.local->mp, (void *)status->response);
    status->id = msg->h.id;
    status->do_free = do_free;
    status->status = TASVIR_RPC_STATUS_PENDING;
    status->response = NULL;
    status->cb = NULL;

    return status;
}

tasvir_rpc_status *tasvir_rpc_async(tasvir_thread *inst, tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(inst, fnptr, true, argp);
    va_end(argp);
    return status;
}

// FIXME: assumes return value is a ptr
void *tasvir_rpc_sync(tasvir_thread *inst, uint64_t timeout_us, tasvir_fnptr fnptr, ...) {
    uint64_t time_end = tasvir_gettime_us() + timeout_us;
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(inst, fnptr, false, argp);
    va_end(argp);
    while (ttls.local->time_us < time_end && status->status == TASVIR_RPC_STATUS_PENDING) {
        rte_delay_us_block(50);
        tasvir_service();
    }
    // FIXME: find a proper way to ensure state is visible
    if (status->status == TASVIR_RPC_STATUS_DONE) {
        while (ttls.local->dstate.last_sync < status->response->h.time_us) {
            rte_delay_us_block(50);
            tasvir_service();
        }
    }
    assert(status->status != TASVIR_RPC_STATUS_DONE || status->response);
    return status->status == TASVIR_RPC_STATUS_DONE ? *(void **)status->response->data : NULL;
}

int tasvir_rpc_register(tasvir_fn_info *fni) {
    ttls.fn_infos[ttls.nr_fns] = *fni;
    HASH_ADD(h_fid, ttls.ht_fid, fid, sizeof(fni->fid), &ttls.fn_infos[ttls.nr_fns]);
    HASH_ADD(h_fnptr, ttls.ht_fnptr, fnptr, sizeof(fni->fnptr), &ttls.fn_infos[ttls.nr_fns]);
    ttls.nr_fns++;
    return 0;
}

static void tasvir_service_rpc(tasvir_msg_rpc *msg) {
    assert(msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST || msg->h.type == TASVIR_MSG_TYPE_RPC_RESPONSE);

    tasvir_fn_info *fni;
    struct rte_ring *ring_tx;

    if (!tasvir_is_thread_id_local(&msg->h.dst_id)) {
        assert(ttls.is_daemon);
        abort();  // not implemented
        // reroute the msg
        // FIXME: populate net header
        ring_tx = ttls.local->ring_ext_tx;
        if (rte_ring_sp_enqueue(ring_tx, msg) != 0) {
            TASVIR_LOG("rte_ring_sp_enqueue failed\n");
            rte_mempool_put(ttls.local->mp, (void *)msg);
        }
        return;
    }

    if (ttls.thread && msg->h.dst_id.idx != ttls.thread->id.idx) {
        assert(ttls.is_daemon);
        ring_tx = ttls.local->istate[msg->h.dst_id.idx].ring_rx;
        if (rte_ring_sp_enqueue(ring_tx, msg) != 0) {
            TASVIR_LOG("rte_ring_sp_enqueue failed\n");
            rte_mempool_put(ttls.local->mp, (void *)msg);
        }
        return;
    }

    HASH_FIND(h_fid, ttls.ht_fid, &msg->fid, sizeof(msg->fid), fni);
    assert(fni);
    TASVIR_LOG("type=%d id=%d fid=%d name=%s argc=%d\n", msg->h.type, msg->h.id, msg->fid, fni->name, fni->argc);

    if (msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        if (ttls.is_daemon) {
            if (tasvir_is_thread_id_local(&msg->h.src_id))
                ring_tx = ttls.local->istate[msg->h.src_id.idx].ring_rx;
            else {
                // FIXME: populate net header
                ring_tx = ttls.local->ring_ext_tx;
                if (rte_ring_sp_enqueue(ring_tx, msg) != 0) {
                    TASVIR_LOG("rte_ring_sp_enqueue failed\n");
                    rte_mempool_put(ttls.local->mp, (void *)msg);
                }
            }

        } else {
            ring_tx = ttls.local->istate[ttls.thread->id.idx].ring_tx;
        }
        fni->fnptr(msg->data, msg->arg_ptrs);
        msg->h.dst_id = msg->h.src_id;
        msg->h.src_id = ttls.thread->id;
        msg->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
        msg->h.time_us = ttls.local->time_us;
        if (rte_ring_sp_enqueue(ring_tx, msg) != 0) {
            TASVIR_LOG("rte_ring_sp_enqueue failed\n");
            rte_mempool_put(ttls.local->mp, (void *)msg);
            return;
        }
    } else if (msg->h.type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        HASH_FIND(h_fid, ttls.ht_fid, &msg->fid, sizeof(msg->fid), fni);
        assert(fni);
        assert(msg->h.id < TASVIR_NR_RPC_MSG);
        tasvir_rpc_status *status = &ttls.status_l[msg->h.id];
        status->status = TASVIR_RPC_STATUS_DONE;
        if (status->do_free)
            rte_mempool_put(ttls.local->mp, (void *)msg);
        else
            status->response = msg;
    }
}

static void tasvir_service_ring(struct rte_ring *ring) {
    tasvir_msg_rpc *msg[TASVIR_RING_SIZE];
    unsigned int count, i;

    count = rte_ring_sc_dequeue_burst(ring, (void **)msg, TASVIR_RING_SIZE, NULL);
    for (i = 0; i < count; i++) {
        tasvir_service_rpc(msg[i]);
    }
}

/* sync */
static inline void tasvir_schedule_sync(tasvir_area_desc *d) {
    if (!d->owner)
        return;

    tasvir_area_header *h_src = d->h;
    tasvir_area_header *h_dst = tasvir_addr_shadow(d->h);
    uint8_t *addr_src = (uint8_t *)d->h;
    uint8_t *addr_dst = tasvir_addr_shadow(d->h);
    tasvir_log_t *addr_log = tasvir_addr_log(d->h);
    size_t len, len_this;

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_container *c = (tasvir_container *)d->h->data;
        len = sizeof(tasvir_area_header) + c->len;
    } else {
        len = d->len;
    }

    uint16_t otid = tasvir_is_thread_local(d->owner) ? d->owner->id.idx : 0;
    uint16_t tid = otid - 1;
    int fail_count = 0;

    if (d == ttls.root_desc) {
        tasvir_local_istate *istate = &ttls.local->istate[otid];
        istate->jobs[istate->nr_jobs++] = (tasvir_sync_job){.version = 0,
                                                            .h_dst = NULL,
                                                            .h_src = NULL,
                                                            .addr_dst = tasvir_addr_shadow(d),
                                                            .addr_src = (uint8_t *)d,
                                                            .addr_log = tasvir_addr_log(d),
                                                            .len = sizeof(tasvir_area_desc)};
    }

    while (len > 0) {
        tid++;
        tid %= TASVIR_NR_THREADS_LOCAL;
        if (ttls.node->threads[tid].status != TASVIR_THREAD_STATUS_RUNNING)
            continue;
        tasvir_local_istate *istate = &ttls.local->istate[tid];
        if (istate->nr_jobs >= sizeof(istate->jobs) / sizeof(istate->jobs[0])) {
            if (fail_count++ >= TASVIR_NR_THREADS_LOCAL) {
                TASVIR_LOG("more jobs than free slots\n");
                abort();
            }
            continue;
        }
        len_this = 1 + (len - 1) % TASVIR_SYNC_JOB_BYTES;
        // in the owner thread addr shadow and addr are swapped
        istate->jobs[istate->nr_jobs++] = (tasvir_sync_job){.version = d->h->version,
                                                            .h_dst = tid == otid ? h_dst : h_src,
                                                            .h_src = tid == otid ? h_src : h_dst,
                                                            .addr_dst = tid == otid ? addr_dst : addr_src,
                                                            .addr_src = tid == otid ? addr_src : addr_dst,
                                                            .addr_log = addr_log,
                                                            .len = len_this};
        addr_src += len_this;
        addr_dst += len_this;
        addr_log += len_this / TASVIR_LOG_UNIT;
        len -= len_this;
    }
}

static inline size_t tasvir_walk_areas(tasvir_area_desc *d) {
    size_t bytes = 0;
    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        tasvir_container *c = (tasvir_container *)d->h->data;
        for (size_t i = 0; i < c->nr_areas; i++)
            bytes += tasvir_walk_areas(&c->descs[i]);
    }
    tasvir_schedule_sync(d);
    return bytes;
}

// FIXME: assumes this is run in the owner thread
static inline size_t tasvir_sync_area(tasvir_sync_job *j) {
    uint8_t leading_ones, leading_zeros;
    uint8_t *addr_dst_end = j->addr_dst + j->len;
    size_t diff, offset, total_bytes = 0;
    while (j->addr_dst < addr_dst_end) {
        offset = TASVIR_LOG_UNIT;
        while (*j->addr_log) {
            leading_zeros = _lzcnt_u64(*j->addr_log);
            *j->addr_log <<= leading_zeros;
            leading_ones = _lzcnt_u64(~*j->addr_log);
            *j->addr_log <<= leading_ones - 1;
            *j->addr_log <<= 1;
            diff = leading_zeros << TASVIR_SHIFT_BIT;
            j->addr_src += diff;
            j->addr_dst += diff;
            offset -= diff;
            diff = leading_ones << TASVIR_SHIFT_BIT;
            memcpy(j->addr_dst, j->addr_src, diff);
            // TASVIR_LOG("%p->%p %lu\n", addr_src, addr_dst, diff);
            total_bytes += diff;
            j->addr_src += diff;
            j->addr_dst += diff;
            offset -= diff;
        }
        j->addr_log++;
        j->addr_dst += offset;
        j->addr_src += offset;
    }

    /* race doesn't matter because everyone is trying to update version to the same value */
    if (total_bytes > 0 && j->h_dst) {
        j->h_src->version = j->version + 1;
        j->h_dst->version = j->version + 1;
        j->h_src->update_us = ttls.local->time_us;
        j->h_dst->update_us = ttls.local->time_us;
    }
    return total_bytes;
}

static inline void tasvir_sync_prep() {
    if (ttls.local->time_us - ttls.local->dstate.last_sync < TASVIR_SYNC_US)
        return;

    // heartbeat: declare unresponsive threads dead
    for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
        if ((ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING) &&
            (ttls.local->time_us - ttls.local->istate[i].update_us > ttls.node->heartbeat_us)) {
            tasvir_kill_thread(&ttls.node->threads[i]);
        }
    }

    ttls.local->barrier_entry = ttls.node->nr_threads;
    ttls.local->barrier_exit = ttls.node->nr_threads;

    for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
        if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING) {
            ttls.local->istate[i].sync = true;
        }
    }
}

static inline size_t tasvir_sync() {
    if (!ttls.thread)
        return 0;

    tasvir_local_istate *istate = &ttls.local->istate[ttls.thread->id.idx];
    if (!istate->sync)
        return 0;

    uint64_t time_us = ttls.local->time_us;
    size_t total_bytes = 0;
    istate->sync = false;

    if (tasvir_barrier_wait(&ttls.local->barrier_entry, TASVIR_BARRIER_ENTER_US) != 0) {
        TASVIR_LOG("tasvir_barrier_wait entry failed\n");
        return 0;
    }

    for (size_t i = 0; i < istate->nr_jobs; i++) {
        total_bytes += tasvir_sync_area(&istate->jobs[i]);
    }
    istate->nr_jobs = 0;

    // FIXME
    // if (ttls.is_daemon) {
    //     rte_memcpy(tasvir_addr_shadow(ttls.root_desc), ttls.root_desc, sizeof(tasvir_area_desc));
    //     total_bytes += sizeof(tasvir_area_desc);
    // }
    istate->sync_cumbytes = total_bytes;

    if (tasvir_barrier_wait(&ttls.local->barrier_exit, TASVIR_BARRIER_EXIT_US) != 0) {
        TASVIR_LOG("tasvir_barrier_wait exit failed\n");
        return total_bytes;
    }

    istate->update_us = tasvir_gettime_us();
    time_us = istate->update_us - time_us;

    if (ttls.is_daemon) {
        ttls.local->time_us = istate->update_us;
        ttls.local->dstate.last_sync = istate->update_us;
        ttls.local->dstate.sync_count++;
        ttls.local->dstate.sync_cumtime_us += time_us;
        for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
            if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING)
                ttls.local->dstate.sync_cumbytes += ttls.local->istate[i].sync_cumbytes;
        }
        tasvir_walk_areas(ttls.root_desc);
    }
    return total_bytes;
}

static inline void tasvir_update_stats() {
    if (ttls.local->time_us - ttls.local->dstate.last_stat < TASVIR_STAT_US)
        return;

    ttls.local->dstate.last_stat = ttls.local->time_us;
    if (ttls.local->dstate.sync_count == 0)
        return;
    TASVIR_LOG("sync count %lu time %luus copied %lukB time/sync %luus copied/sync %lukB\n",
               ttls.local->dstate.sync_count, ttls.local->dstate.sync_cumtime_us,
               ttls.local->dstate.sync_cumbytes / 1000,
               ttls.local->dstate.sync_cumtime_us / ttls.local->dstate.sync_count,
               ttls.local->dstate.sync_cumbytes / (1000 * ttls.local->dstate.sync_count));
    ttls.local->dstate.sync_count = 0;
    ttls.local->dstate.sync_cumtime_us = 0;
    ttls.local->dstate.sync_cumbytes = 0;
}

static inline void tasvir_service_daemon() {
    /* update time */
    ttls.local->time_us = tasvir_gettime_us();
    ttls.local->istate[TASVIR_THREAD_DAEMON_IDX].update_us = ttls.local->time_us;
    /* service rings */
    for (size_t i = 0; i < TASVIR_NR_THREADS_LOCAL; i++) {
        if (ttls.node->threads[i].status == TASVIR_THREAD_STATUS_RUNNING ||
            ttls.node->threads[i].status == TASVIR_THREAD_STATUS_BOOTING) {
            tasvir_service_ring(ttls.local->istate[i].ring_tx);
        }
    }
    tasvir_update_stats();
    tasvir_sync_prep();
}

static inline void tasvir_service_client() {
    /* service rings */
    if (likely(ttls.thread != NULL))
        ttls.local->istate[ttls.thread->id.idx].update_us = ttls.local->time_us;
    tasvir_service_ring(ttls.local->istate[ttls.thread ? ttls.thread->id.idx : TASVIR_THREAD_DAEMON_IDX].ring_rx);
}

void tasvir_service() {
    if (ttls.is_daemon) {
        tasvir_service_daemon();
    } else {
        tasvir_service_client();
    }
    tasvir_sync();
}
