#include <fcntl.h>
#include <numaif.h>
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

    ttld.fd = shm_open("tasvir", shm_oflag, shm_mode);
    if (ttld.fd == -1) {
        LOG_ERR("shm_open failed (%s)", strerror(errno));
        return -1;
    }
    if (ftruncate(ttld.fd, TASVIR_SIZE_MAP)) {
        LOG_ERR("ftruncate failed (%s)", strerror(errno));
        return -1;
    }
    base =
        mmap((void *)TASVIR_ADDR_BASE, TASVIR_SIZE_MAP, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, ttld.fd, 0);
    if (base != (void *)TASVIR_ADDR_BASE) {
        LOG_ERR("mmap failed asked %p got %p", (void *)TASVIR_ADDR_BASE, base);
        return -1;
    }
    base = mmap((void *)TASVIR_ADDR_DATA_RO, TASVIR_SIZE_DATA * 2, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED,
                ttld.fd, 0);
    if (base != (void *)TASVIR_ADDR_DATA_RO) {
        LOG_ERR("mmap failed asked %p got %p", (void *)TASVIR_ADDR_DATA_RO, base);
        return -1;
    }
    madvise((void *)TASVIR_ADDR_DATA_RO, TASVIR_SIZE_DATA * 2, MADV_HUGEPAGE);

    ttld.ndata = (void *)TASVIR_ADDR_LOCAL;
    ttld.tdata = &ttld.ndata->tdata[TASVIR_THREAD_DAEMON_IDX];

#ifdef TASVIR_DAEMON
    char *is_root = getenv("TASVIR_IS_ROOT");
    if (is_root && strcmp(is_root, "1") == 0) {
        LOG_INFO("claiming the root area ownership (TASVIR_IS_ROOT is set)")
        ttld.is_root = 1;
    }
    memset(ttld.ndata, 0, sizeof(tasvir_local_ndata));

    /* boot mutex */
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&ttld.ndata->mutex_init, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);
    ttld.ndata->barrier_end_tsc = 0;
    ttld.ndata->barrier_cnt = -1;
    ttld.ndata->barrier_seq = 1;

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
    ttld.ndata->ring_mem_pending =
        rte_ring_create("tasvir_mem_pending", TASVIR_RING_EXT_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ttld.ndata->ring_ext_tx) {
        LOG_ERR("failed to create external tx ring");
        return -1;
    }
    if (!ttld.ndata->ring_mem_pending) {
        LOG_ERR("failed to create pending memory message ring");
        return -1;
    }
    LOG_DBG("created rings ext_tx=%p mem_pending=%p", (void *)ttld.ndata->ring_ext_tx,
            (void *)ttld.ndata->ring_mem_pending);

    /* timing */
    ttld.ndata->sync_int_us = TASVIR_SYNC_INTERNAL_US;
    ttld.ndata->sync_ext_us = TASVIR_SYNC_EXTERNAL_US;
    ttld.ndata->tsc2usec_mult = 1E6 / rte_get_tsc_hz();
    ttld.ndata->boot_us = ttld.ndata->time_us = tasvir_time_us();

    /* ids */
    ttld.ndata->boot_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x00, 0x0f, 0xff}}};
    ttld.ndata->boot_tid.idx = -1;
    ttld.ndata->boot_tid.pid = -1;
    ttld.ndata->memcast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x01, 0x0f, 0xff}}};
    ttld.ndata->memcast_tid.idx = -1;
    ttld.ndata->memcast_tid.pid = -1;
    ttld.ndata->rpccast_tid.nid = (tasvir_nid){.mac_addr = {{0x01, 0x00, 0x5e, 0x02, 0x0f, 0xff}}};
    ttld.ndata->rpccast_tid.idx = -1;
    ttld.ndata->rpccast_tid.pid = -1;
#else
    /* wait for 10^10 cycles (5s at 2GHz) for the daemon to boot */
    uint64_t end_tsc = __rdtsc() + (uint64_t)1E10;
    bool is_daemon_running = false;
    do {
        /* ttld.tdata is daemon's at this stage so the following test is fine */
        is_daemon_running = ttld.tdata->state == TASVIR_THREAD_STATE_RUNNING;
        if (is_daemon_running)
            break;
        rte_delay_ms(1);
    } while (__rdtsc() < end_tsc);
    if (!is_daemon_running) {
        LOG_ERR("daemon not initialized");
        return -1;
    }
#endif
    ttld.tsc2usec_mult = ttld.ndata->tsc2usec_mult;

    return 0;
}

static int tasvir_init_root() {
    ttld.root_desc = (tasvir_area_desc *)TASVIR_ADDR_DATA;
    tasvir_area_desc *d_ret;

#ifdef TASVIR_DAEMON
    ttld.root_desc->pd = NULL;
    ttld.root_desc->owner = NULL;
    ttld.root_desc->h = (void *)TASVIR_ALIGN((uintptr_t)ttld.root_desc + sizeof(tasvir_area_desc));
    ttld.root_desc->offset_log_end =
        TASVIR_ALIGN(sizeof(tasvir_area_header) + TASVIR_NR_AREAS * sizeof(tasvir_area_desc));
    ttld.root_desc->type = TASVIR_AREA_TYPE_CONTAINER;
    strcpy(ttld.root_desc->name, "/");
    ttld.root_desc->len = TASVIR_SIZE_DATA - GB;
    ttld.root_desc->nr_areas_max = TASVIR_NR_AREAS;
#endif
    if (ttld.is_root) {
        d_ret = tasvir_new(*ttld.root_desc);
    } else {
        d_ret = tasvir_attach_wait(15 * S2US, "/");
    }

    if (!d_ret || !d_ret->h) {
        LOG_ERR("root not initialized");
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
    ether_ntoa_r(&ttld.ndata->mac_addr, &name[strlen(name)]);

#ifdef TASVIR_DAEMON
    /* id and address */
    /* initializing boot_us so that could later use this node's clock rather than root's */
    ttld.node_desc = tasvir_new((tasvir_area_desc){.pd = ttld.root_desc,
                                                   .type = TASVIR_AREA_TYPE_NODE,
                                                   .name0 = *(tasvir_str_static *)name,
                                                   .len = sizeof(tasvir_node),
                                                   .nr_areas_max = 0});
    if (!ttld.node_desc) {
        LOG_ERR("failed to allocate node");
        return -1;
    }
    ttld.node = tasvir_data(ttld.node_desc);
    memset(ttld.node, 0, sizeof(tasvir_node));
    memcpy(&ttld.node->nid.mac_addr, &ttld.ndata->mac_addr, ETH_ALEN);
    ttld.node->heartbeat_us = TASVIR_HEARTBEAT_US;

    /* time */
    tasvir_log(ttld.node, sizeof(tasvir_node));
#else
    ttld.node_desc = tasvir_attach_wait(500 * MS2US, name);
    if (!ttld.node_desc || !ttld.node_desc->h->d) {
        LOG_ERR("node not initiliazed yet");
        return -1;
    }
    ttld.node = tasvir_data(ttld.node_desc);

    /* daemon alive? */
    uint64_t time_us = tasvir_time_us();
    if (!ttld.node_desc->h) {
        LOG_ERR("daemon is inactive");
        return -1;
    } else if (time_us - ttld.ndata->time_us > ttld.node_desc->sync_int_us) {
        LOG_ERR("daemon has not checked in for %lu us (> %lu), last activity %lu", time_us - ttld.node_desc->h->time_us,
                ttld.node_desc->sync_int_us, ttld.node_desc->h->time_us);
        return -1;
    }
#endif

    return 0;
}

tasvir_thread *tasvir_init_thread(pid_t pid) {
    tasvir_thread *t = NULL;
    tasvir_str tid_str;

#ifdef TASVIR_DAEMON
    /* find a free thread id */
    uint16_t idx;
    for (idx = 0; idx < TASVIR_NR_THREADS_LOCAL; idx++) {
        if (ttld.ndata->tdata[idx].state != TASVIR_THREAD_STATE_RUNNING &&
            ttld.ndata->tdata[idx].state != TASVIR_THREAD_STATE_BOOTING)
            break;
    }

    if (idx == TASVIR_NR_THREADS_LOCAL)
        return NULL;

    /* populate thread */
    t = &ttld.node->threads[idx];
    memset(t, 0, sizeof(*t));
    t->state = TASVIR_THREAD_STATE_BOOTING;
    t->tid.nid = ttld.node->nid;
    t->tid.idx = idx;
    t->tid.pid = pid;
    tasvir_log(t, sizeof(*t));

    tasvir_local_tdata *tdata = &ttld.ndata->tdata[idx];
    memset(tdata, 0, sizeof(*tdata));
    tdata->state = TASVIR_THREAD_STATE_BOOTING;

    /* rings */
    tasvir_str tmp;
    sprintf(tmp, "tasvir_tx_%d", idx);
    tdata->ring_tx = rte_ring_create(tmp, TASVIR_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    sprintf(tmp, "tasvir_rx_%d", idx);
    tdata->ring_rx = rte_ring_create(tmp, TASVIR_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (!tdata->ring_tx || !tdata->ring_rx) {
        tasvir_tid_str(&t->tid, tid_str, sizeof(tid_str));
        LOG_ERR("failed to create rings for tid %s", tid_str);
        return NULL;
    }
#else
    /* FIXME: deadlock on crash */
    pthread_mutex_lock(&ttld.ndata->mutex_init);
    int rc = tasvir_rpc_wait(S2US, (void **)&t, ttld.node_desc, (tasvir_fnptr)&tasvir_init_thread, pid);
    pthread_mutex_unlock(&ttld.ndata->mutex_init);
    if (rc)
        return NULL;
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
#endif

    tasvir_tid_str(&t->tid, tid_str, sizeof(tid_str));
    LOG_INFO("addr=%p tx_ring=%p rx_ring=%p tid=%s", (void *)t, (void *)tdata->ring_tx, (void *)tdata->ring_rx,
             tid_str);
    return t;
}

int tasvir_init_finish(tasvir_thread *t) {
    tasvir_local_tdata *tdata = &ttld.ndata->tdata[t->tid.idx];
    if (tdata->state != TASVIR_THREAD_STATE_BOOTING) {
        LOG_ERR("calling thread is not in the BOOTING state");
        return -1;
    }
    assert(ttld.thread && ttld.node);

#ifdef TASVIR_DAEMON
    /* backfill area owners */
    if (t == ttld.thread) {
        if (ttld.is_root) {
            if (tasvir_update_owner(ttld.root_desc, ttld.thread)) {
                LOG_ERR("failed to update the root area owner");
                return -1;
            }
        }
        if (tasvir_update_owner(ttld.node_desc, ttld.thread)) {
            LOG_ERR("failed to update the node area owner");
            return -1;
        }
        if (tasvir_area_add_user_wait(100 * MS2US, ttld.root_desc, ttld.node, -1)) {
            LOG_ERR("failed to add to the root area subscriber list");
            return -1;
        }
        if (tasvir_area_add_user_wait(100 * MS2US, ttld.node_desc, ttld.node, -1)) {
            LOG_ERR("failed to add to the node area subscriber list");
            return -1;
        }
    }
    tasvir_log(&t->state, sizeof(t->state));
    t->state = TASVIR_THREAD_STATE_RUNNING;
    tdata->state = TASVIR_THREAD_STATE_RUNNING;
    tdata->state_req = tdata->state;
#else
    int retval = -1;
    if (tasvir_rpc_wait(S2US, (void **)&retval, ttld.node_desc, (tasvir_fnptr)&tasvir_init_finish, t) || retval) {
        return -1;
    }
#endif

    if (t == ttld.thread) {
        if (!tasvir_is_running()) {
            LOG_ERR("thread is not in the RUNNING state");
            return -1;
        }
    }

    char tid_str[48];
    tasvir_tid_str(&t->tid, tid_str, sizeof(tid_str));
    LOG_INFO("tid=%s addr=%p", tid_str, (void *)t);

#ifdef TASVIR_DAEMON
    tasvir_sync_external_area(ttld.node_desc);
#endif
    return 0;
}

tasvir_area_desc *tasvir_init() {
    if (ttld.node || ttld.thread) {
        LOG_ERR("already initialized");
        return ttld.root_desc;
    }
    /* ttld has static storage and is automatically zero-initialized */

    tasvir_init_rpc();

    if (tasvir_init_dpdk()) {
        LOG_ERR("tasvir_init_dpdk failed");
        return NULL;
    }

    if (tasvir_init_local()) {
        LOG_ERR("tasvir_init_local failed");
        return NULL;
    }

#ifdef TASVIR_DAEMON
    if (tasvir_init_port()) {
        LOG_ERR("tasvir_init_port failed");
        return NULL;
    }
#endif

    if (tasvir_init_root()) {
        LOG_ERR("tasvir_init_root failed");
        return NULL;
    }

    if (tasvir_init_node()) {
        LOG_ERR("tasvir_init_node failed");
        return NULL;
    }

    ttld.thread = tasvir_init_thread(getpid());
    if (!ttld.thread) {
        LOG_ERR("tasvir_init_thread failed");
        return NULL;
    }
    ttld.tdata = &ttld.ndata->tdata[ttld.thread->tid.idx];

    if (tasvir_init_finish(ttld.thread)) {
        LOG_ERR("tasvir_init_finish failed");
        return NULL;
    }

    return ttld.root_desc;
}
