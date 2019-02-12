#include <fcntl.h>
#include <rte_eal.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tasvir.h"

static int tasvir_init_local() {
    void *base;
#ifdef TASVIR_DAEMON
    int shm_oflag = O_CREAT | O_EXCL | O_RDWR;
    mode_t shm_mode = S_IRUSR | S_IWUSR;
#else
    int shm_oflag = O_RDWR;
    mode_t shm_mode = 0;
#endif
    ptrdiff_t size_whole = TASVIR_ADDR_END - TASVIR_ADDR_BASE;

    ttld.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttld.fd == -1)
        return -1;
    if (ftruncate(ttld.fd, size_whole)) {
        LOG_ERR("ftruncate failed (%s)", strerror(errno));
        return -1;
    }
    base = mmap((void *)TASVIR_ADDR_BASE, size_whole, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttld.fd, 0);
    if (base != (void *)TASVIR_ADDR_BASE) {
        LOG_ERR("mmap failed");
        return -1;
    }
    madvise((void *)TASVIR_ADDR_BASE, size_whole, MADV_HUGEPAGE);

    ttld.ndata = (void *)TASVIR_ADDR_LOCAL;
    ttld.tdata = &ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX];

#ifdef TASVIR_DAEMON
    memset(ttld.ndata, 0, sizeof(tasvir_local_ndata));
    /* boot mutex */
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&ttld.ndata->mutex_init, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);
    ttld.ndata->barrier_end_tsc = 0;
    atomic_store(&ttld.ndata->barrier_entry, -1);
    atomic_store(&ttld.ndata->barrier_seq, 0);

    /* mempool */
    ttld.ndata->mp = rte_pktmbuf_pool_create("mempool", TASVIR_MBUF_POOL_SIZE, TASVIR_MBUF_CORE_CACHE_SIZE, 0,
                                             RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!ttld.ndata->mp) {
        LOG_ERR("failed to create pkt mempool");
        return -1;
    }

    /* tx ring */
    ttld.ndata->ring_ext_tx =
        rte_ring_create("tasvir_ext_tx", TASVIR_RING_EXT_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    LOG_DBG("created ring for external tx %p", (void *)ttld.ndata->ring_ext_tx);
    if (ttld.ndata->ring_ext_tx == NULL) {
        LOG_ERR("failed to create external rings");
        return -1;
    }

    /* timing */
    ttld.ndata->sync_int_us = TASVIR_SYNC_INTERNAL_US;
    ttld.ndata->sync_ext_us = TASVIR_SYNC_EXTERNAL_US;
    ttld.ndata->tsc2usec_mult = 1E6 / rte_get_tsc_hz();

    /* ids */
    ttld.ndata->update_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x0f, 0xff}}};
    ttld.ndata->update_tid.idx = -1;
    ttld.ndata->update_tid.pid = -1;
    ttld.ndata->rootcast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x0f, 0x01}}};
    ttld.ndata->rootcast_tid.idx = -1;
    ttld.ndata->rootcast_tid.pid = -1;
    ttld.ndata->nodecast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x0f, 0x02}}};
    ttld.ndata->nodecast_tid.idx = -1;
    ttld.ndata->nodecast_tid.pid = -1;
#else
    /* wait for 15s for the daemon to boot */
    uint64_t end_tsc = tasvir_rdtsc() + tasvir_usec2tsc(3 * S2US);
    while (tasvir_rdtsc() < end_tsc && ttld.tdata->state != TASVIR_THREAD_STATE_RUNNING) {
        rte_delay_ms(1);
    }
    if (ttld.tdata->state != TASVIR_THREAD_STATE_RUNNING) {
        LOG_ERR("daemon not initialized");
        return -1;
    }
#endif

    return 0;
}

static int tasvir_init_root() {
    ttld.root_desc = (tasvir_area_desc *)TASVIR_ADDR_ROOT_DESC;
    tasvir_area_desc *d_ret;

    if (ttld.is_root) {
        d_ret = tasvir_new((tasvir_area_desc){.pd = NULL,
                                              .owner = NULL,
                                              .type = TASVIR_AREA_TYPE_CONTAINER,
                                              .name = "root",
                                              .len = TASVIR_SIZE_DATA - 2 * TASVIR_HUGEPAGE_SIZE,
                                              .nr_areas_max = TASVIR_NR_AREAS_MAX});
    } else {
        d_ret = tasvir_attach_wait(NULL, "root", NULL, false, 15 * S2US);
    }

    if (!d_ret || !d_ret->active) {
        LOG_ERR("root not initialized")
        return -1;
    } else if (d_ret != ttld.root_desc) {
        LOG_ERR("returned address doesn't match root_desc address")
        return -1;
    }

    return 0;
}

static int tasvir_init_node() {
    /* FIXME: assuming a clean boot */
    tasvir_str name = "node-";
    ether_format_addr(&name[strlen(name)], sizeof(name) - strlen(name), &ttld.ndata->mac_addr);

#ifdef TASVIR_DAEMON
    /* id and address */
    /* initializing boot_us so that could be later use this node's clock rather than root's */
    ttld.node_desc = tasvir_new((tasvir_area_desc){.pd = ttld.root_desc,
                                                   .owner = NULL,
                                                   .type = TASVIR_AREA_TYPE_NODE,
                                                   .name0 = *(tasvir_str_static *)name,
                                                   .len = sizeof(tasvir_node),
                                                   .nr_areas_max = 0,
                                                   .boot_us = tasvir_gettime_us()});
    if (!ttld.node_desc) {
        LOG_ERR("failed to allocate node");
        return -1;
    }
    ttld.node = tasvir_data(ttld.node_desc);
    memset(ttld.node, 0, sizeof(tasvir_node));
    ether_addr_copy(&ttld.ndata->mac_addr, &ttld.node->nid.mac_addr);
    ttld.node->heartbeat_us = TASVIR_HEARTBEAT_US;

    /* time */
    tasvir_log_write(ttld.node, sizeof(tasvir_node));
#else
    ttld.node_desc = tasvir_attach_wait(ttld.root_desc, name, NULL, false, 500 * MS2US);
    if (!ttld.node_desc || !ttld.node_desc->h->active) {
        LOG_ERR("node not initiliazed yet");
        return -1;
    }
    ttld.node = tasvir_data(ttld.node_desc);

    tasvir_local_tdata *daemon_tdata = &ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX];

    /* daemon alive? */
    uint64_t time_us = tasvir_gettime_us();
    if (!ttld.node_desc->active) {
        LOG_ERR("daemon is inactive");
        return -1;
    } else if (time_us > daemon_tdata->update_us && time_us - daemon_tdata->update_us > ttld.node_desc->sync_int_us) {
        LOG_ERR("daemon has been stale for %lu us (> %lu), last activity %lu", time_us - ttld.node_desc->h->update_us,
                ttld.node_desc->sync_int_us, ttld.node_desc->h->update_us);
        return -1;
    }
#endif

    return 0;
}

tasvir_thread *tasvir_init_thread(pid_t pid, uint16_t core) {
    tasvir_thread *t = NULL;

#ifdef TASVIR_DAEMON
    /* find a free thread id */
    uint16_t tid;
    for (tid = 0; tid < TASVIR_NR_THREADS_LOCAL; tid++) {
        if (ttld.ndata->tdata[tid].state != TASVIR_THREAD_STATE_RUNNING &&
            ttld.ndata->tdata[tid].state != TASVIR_THREAD_STATE_BOOTING)
            break;
    }

    if (tid == TASVIR_NR_THREADS_LOCAL)
        return NULL;

    /* populate thread */
    t = &ttld.node->threads[tid];
    t->core = core;
    t->tid.nid = ttld.node->nid;
    t->tid.idx = tid;
    t->tid.pid = pid;
    tasvir_log_write(t, sizeof(tasvir_thread));

    tasvir_local_tdata *tdata = &ttld.ndata->tdata[tid];
    tasvir_str tmp;
    /* rings */
    sprintf(tmp, "tasvir_tx_%d", tid);
    tdata->ring_tx =
        rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
    sprintf(tmp, "tasvir_rx_%d", tid);
    tdata->ring_rx =
        rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
    LOG_DBG("created rings tx=%p rx=%p for tid=%d", (void *)tdata->ring_tx, (void *)tdata->ring_rx, tid);
    if (tdata->ring_tx == NULL || tdata->ring_rx == NULL) {
        LOG_ERR("failed to create rings for tid %d", tid);
        return NULL;
    }
    tdata->state = TASVIR_THREAD_STATE_BOOTING;
#else
    /* FIXME: deadlock on crash */
    pthread_mutex_lock(&ttld.ndata->mutex_init);
    int rc = tasvir_rpc_wait(S2US, (void **)&t, ttld.node_desc, (tasvir_fnptr)&tasvir_init_thread, pid, core);
    pthread_mutex_unlock(&ttld.ndata->mutex_init);
    if (rc != 0)
        return NULL;
#endif

    LOG_INFO("addr=%p tid=%d core=%d pid=%d", (void *)t, t->tid.idx, t->core, t->tid.pid);

    return t;
}

int tasvir_init_finish(tasvir_thread *t) {
    if (ttld.ndata->tdata[t->tid.idx].state != TASVIR_THREAD_STATE_BOOTING) {
        LOG_ERR("called from a thread that is not in the BOOTING state");
        return -1;
    }

#ifdef TASVIR_DAEMON
    t->active = true;
    tasvir_log_write(&t->active, sizeof(t->active));

    /* backfill area owners */
    if (t == ttld.thread) {
        if (ttld.is_root) {
            ttld.node_desc->owner = ttld.thread;
            ttld.root_desc->owner = ttld.thread;
            tasvir_log_write(&ttld.node_desc->owner, sizeof(ttld.node_desc->owner));
            tasvir_log_write(&ttld.root_desc->owner, sizeof(ttld.root_desc->owner));
        } else if (!tasvir_update_owner(ttld.node_desc, ttld.thread)) {
            return -1;
        }
    }
#else
    int retval = -1;
    if (tasvir_rpc_wait(S2US, (void **)&retval, ttld.node_desc, (tasvir_fnptr)&tasvir_init_finish, t) != 0 ||
        retval != 0) {
        return -1;
    }
#endif

    if (t == ttld.thread)
        ttld.tdata->state = TASVIR_THREAD_STATE_RUNNING;

    LOG_INFO("tid=%d core=%d pid=%d", t->tid.idx, t->core, t->tid.pid);
    return 0;
}

tasvir_area_desc *tasvir_init(uint16_t core) {
    if (ttld.node || ttld.thread) {
        LOG_ERR("tasvir_init may have already been called");
        return NULL;
    }

    /* ttld has static storage and is automatically zero-initialized */

    tasvir_init_rpc();

    LOG_INFO("initializing dpdk");
    if (tasvir_init_dpdk(core) != 0) {
        LOG_ERR("tasvir_init_dpdk failed");
        return NULL;
    }

    LOG_INFO("initializing local control memory");
    if (tasvir_init_local() != 0) {
        LOG_ERR("tasvir_init_local failed");
        return NULL;
    }

#ifdef TASVIR_DAEMON
    LOG_INFO("initializing network port");
    if (tasvir_init_port() != 0) {
        LOG_ERR("tasvir_init_port failed");
        return NULL;
    }
#endif

    LOG_INFO("initializing root area");
    if (tasvir_init_root() != 0) {
        LOG_ERR("tasvir_init_root failed");
        return NULL;
    }

    LOG_INFO("initializing node area");
    if (tasvir_init_node() != 0) {
        LOG_ERR("tasvir_init_node failed");
        return NULL;
    }

    LOG_INFO("initializing thread");
    ttld.thread = tasvir_init_thread(getpid(), core);
    if (!ttld.thread) {
        LOG_ERR("tasvir_init_thread failed");
        return NULL;
    }
    ttld.tdata = &ttld.ndata->tdata[ttld.thread->tid.idx];

    LOG_INFO("finializing initialization");
    if (tasvir_init_finish(ttld.thread) != 0) {
        LOG_ERR("tasvir_init_finish failed");
        return NULL;
    }

    return ttld.root_desc;
}
