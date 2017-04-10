#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
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

#define PAGE_SIZE (4096)
#define ROUND_DOWN(x, l) ((x) & (~(l - 1)))
#define ROUND_UP(x, l) (ROUND_DOWN((x) + l - 1, l))

#define TASVIR_AREA_BYTES (32 * 1024 * 1024)
#define TASVIR_LOG_GRAN (1UL << 9)  // 1 bit per cacheline
#define TASVIR_RING_SIZE (256)

#define TASVIR_NR_ROOT_AREAS (4096)
#define TASVIR_NR_FN (4096)
#define TASVIR_NR_NODES (1024)
#define TASVIR_NR_RPC_MSG (65535)

#define TASVIR_SIZE_GLOBAL (1UL << 42)
#define TASVIR_SIZE_SHADOW (TASVIR_SIZE_GLOBAL / TASVIR_LOG_GRAN)
#define TASVIR_SIZE_LOCAL (sizeof(tasvir_local) + TASVIR_SIZE_SHADOW + TASVIR_SIZE_GLOBAL)
#define TASVIR_SIZE_WHOLE                                                                             \
    ((1 + TASVIR_NR_ROOT_AREAS) * ROUND_UP(sizeof(tasvir_area_desc), PAGE_SIZE) + TASVIR_SIZE_LOCAL + \
     TASVIR_SIZE_GLOBAL)
#define TASVIR_ROOT_DESC_ADDR (0x0000100000000000UL)
#define TASVIR_ROOT_AREA_ADDR (TASVIR_ROOT_DESC_ADDR + PAGE_SIZE)

typedef struct { tasvir_str str; } tasvir_str_static;

static tasvir_area_desc *root_desc, *local_desc, *node_desc;
static tasvir_local *this_local = NULL;
static tasvir_node *this_node = NULL;
static tasvir_instance *this_instance = NULL;
static bool is_tasvir_process = false;

static int tasvir_nr_fn = 0;
static tasvir_fn_info fn_infos[TASVIR_NR_FN];
static tasvir_fn_info *ht_fid = NULL, *ht_fnptr = NULL;
static tasvir_rpc_status status_l[TASVIR_NR_RPC_MSG];

static uint16_t tasvir_msg_id = 0;

/* function prototypes and rpc methods */
static inline tasvir_instance *tasvir_init_instance(uint16_t core, uint8_t type);
static void
tasvir_init_instance_rpc(void *ret, void **args) {
    *(tasvir_instance **)ret = tasvir_init_instance(*(uint16_t *)args[0], *(uint8_t *)args[1]);
}
static inline tasvir_area_desc *tasvir_new2(tasvir_area_desc *pd, tasvir_instance *owner, uint8_t type,
                                            tasvir_str_static name, size_t len, uint64_t stale_us, int nr_areas_max);
static void
tasvir_new2_rpc(void *ret, void **args) {
    *(tasvir_area_desc **)ret =
        tasvir_new2(*(tasvir_area_desc **)args[0], *(tasvir_instance **)args[1], *(uint8_t *)args[2],
                    *(tasvir_str_static *)args[3], *(size_t *)args[4], *(uint64_t *)args[5], *(int *)args[6]);
}
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, char *name);
static void
tasvir_delete_rpc(void *ret, void **args) {
    *(int *)ret = tasvir_delete(*(tasvir_area_desc **)args[0]);
}

static inline uint64_t
tasvir_gettime_us_pre(void) {
    return 1E6 * rte_rdtsc() / rte_get_tsc_hz();
}

static inline uint64_t
tasvir_gettime_us(void) {
    return 1E6 * rte_rdtsc() / this_node->tsc_hz;
}

/* initializtion */

static void
tasvir_init_rpc() {
    tasvir_fn_info fni_init_instance = {
        .fnptr = &tasvir_init_instance_rpc,
        .name = "tasvir_init_instance",
        .fid = 1,
        .argc = 2,
        .ret_len = sizeof(tasvir_instance *),
        .arg_lens = {sizeof(tasvir_instance *), sizeof(uint16_t), sizeof(uint8_t)},

    };
    tasvir_fn_info fni_new = {.fnptr = &tasvir_new2_rpc,
                              .name = "tasvir_new2",
                              .fid = 2,
                              .argc = 7,
                              .ret_len = sizeof(tasvir_area_desc *),
                              .arg_lens = {sizeof(tasvir_area_desc *), sizeof(tasvir_instance *), sizeof(uint8_t),
                                           sizeof(tasvir_str), sizeof(size_t), sizeof(uint64_t), sizeof(int)}};
    tasvir_fn_info fni_delete = {
        .fnptr = &tasvir_delete_rpc,
        .name = "tasvir_delete",
        .fid = 3,
        .argc = 1,
        .ret_len = sizeof(int),
        .arg_lens = {sizeof(tasvir_area_desc *)},
    };
    tasvir_rpc_register(&fni_init_instance);
    tasvir_rpc_register(&fni_new);
    tasvir_rpc_register(&fni_delete);
}
static int
tasvir_init_dpdk(uint16_t core) {
    int argc = 0, retval;
    char *argv[64];
    char core_str[16], mem_str[16];
    snprintf(core_str, sizeof(core_str), "%d", core);
    snprintf(mem_str, sizeof(mem_str), "128,128");
    argv[argc++] = "tasvir";
    argv[argc++] = "-l";
    argv[argc++] = core_str;
    argv[argc++] = "-n";
    argv[argc++] = "4";
    argv[argc++] = "--log-level";
    argv[argc++] = "7";
    argv[argc++] = "--socket-mem";
    argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
    argv[argc++] = is_tasvir_process ? "primary" : "secondary";
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        fprintf(stderr, "tasvir_init_dpdk: rte_eal_init failed\n");
        return -1;
    }
    return 0;
}

static int
tasvir_init_root(uint16_t core, uint8_t type) {
    int i;
    tasvir_str tmp;
    tasvir_area_desc *d_ret;
    root_desc = (tasvir_area_desc *)TASVIR_ROOT_DESC_ADDR;

    if (type == TASVIR_INSTANCE_TYPE_ROOT) {
        d_ret =
            tasvir_new(NULL, NULL, TASVIR_AREA_TYPE_CONTAINER, "root", TASVIR_SIZE_WHOLE, 5000, TASVIR_NR_ROOT_AREAS);
        assert(d_ret == root_desc);
        local_desc = tasvir_new(root_desc, NULL, TASVIR_AREA_TYPE_LOCAL, "local", TASVIR_SIZE_GLOBAL, 5000, 0);
    } else {
        d_ret = tasvir_attach(NULL, "root");
        assert(d_ret == root_desc);
        local_desc = tasvir_attach(root_desc, "local");
    }
    assert(local_desc);
    assert(local_desc->h);
    this_local = (tasvir_local *)local_desc->h->data;

    if (is_tasvir_process) {
        /* shadow log and scratch setup */
        this_local->shadow_diff = root_desc - this_local + sizeof(tasvir_local);
        this_local->scratch_diff = this_local->shadow_diff + ;
        /* mempool */
        this_local->mp =
            rte_pktmbuf_pool_create("mempool", 16 * 1024, 256, 0, 2048 + RTE_PKTMBUF_HEADROOM, rte_socket_id());

        /* rings */
        this_local->rings_discovery.tx = rte_ring_create("tasvir_tx_disc", TASVIR_RING_SIZE,
                                                         rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        this_local->rings_discovery.rx = rte_ring_create("tasvir_rx_disc", TASVIR_RING_SIZE,
                                                         rte_lcore_to_socket_id(core), RING_F_SP_ENQ | RING_F_SC_DEQ);
        for (i = 0; i < TASVIR_NR_INSTANCES_LOCAL; i++) {
            sprintf(tmp, "tasvir_tx_%d", i);
            this_local->rings[i].tx =
                rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(i), RING_F_SP_ENQ | RING_F_SC_DEQ);
            sprintf(tmp, "tasvir_rx_%d", i);
            this_local->rings[i].rx =
                rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(i), RING_F_SP_ENQ | RING_F_SC_DEQ);
        }
    }

    return 0;
}

static int
tasvir_init_node() {
    uint64_t time_us;

    // FIXME: assuming a clean boot
    if (is_tasvir_process) {
        /* id and address */
        node_desc = tasvir_new(root_desc, NULL, TASVIR_AREA_TYPE_NODE, "node-68:05:ca:27:99:48", 1024 * 1024, 5000, 0);
        this_node = (tasvir_node *)node_desc->h->data;
        sscanf("68:05:ca:27:99:48", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &this_node->id.ethaddr[0],
               &this_node->id.ethaddr[1], &this_node->id.ethaddr[2], &this_node->id.ethaddr[3],
               &this_node->id.ethaddr[4], &this_node->id.ethaddr[5]);

        /* time */
        this_node->tsc_hz = rte_get_tsc_hz();
        time_us = tasvir_gettime_us();
    } else {
        node_desc = tasvir_attach(root_desc, "node-68:05:ca:27:99:48");
        this_node = (tasvir_node *)node_desc->h->data;

        /* daemon alive? */
        time_us = tasvir_gettime_us();
        if (!node_desc->h->active) {
            fprintf(stderr, "tasvir_init: daemon is inactive\n");
            return -1;
        } else if (time_us > node_desc->h->update_us && time_us - node_desc->h->update_us > node_desc->h->stale_us) {
            fprintf(stderr, "tasvir_init: daemon has been stale for %lu us (> %lu), last activity %lu\n",
                    time_us - node_desc->h->update_us, node_desc->h->stale_us, node_desc->h->update_us);
            return -1;
        }
    }

    return 0;
}

static inline tasvir_instance *
tasvir_init_instance(uint16_t core, uint8_t type) {
    tasvir_instance *inst = NULL;
    bool is_local = (type == TASVIR_INSTANCE_TYPE_ROOT || type == TASVIR_INSTANCE_TYPE_DAEMON) ||
                    ((this_instance && is_tasvir_process));

    if (!is_local) {
        return tasvir_rpc_sync(10000, (tasvir_fnptr)&tasvir_init_instance_rpc, core, type);
    }

    // find instance id
    for (int i = 0; i < TASVIR_NR_INSTANCES_LOCAL; i++) {
        if (!this_node->instances[i].active) {
            // populate instance
            inst = &this_node->instances[i];
            memcpy(inst->id.node_id.ethaddr, this_node->id.ethaddr, ETHER_ADDR_LEN);
            inst->core = core;
            inst->type = type;
            inst->id.port_id = i;
            inst->active = true;
            break;
        }
    }
    this_node->nr_instances++;

    return inst;
}

tasvir_area_desc *
tasvir_init(uint16_t core, uint8_t type) {
    assert(!this_node && !this_instance);
    is_tasvir_process = type == TASVIR_INSTANCE_TYPE_DAEMON || type == TASVIR_INSTANCE_TYPE_ROOT;

    if (tasvir_init_dpdk(core)) {
        fprintf(stderr, "tasvir_init: tasvir_init_dpdk failed\n");
        return MAP_FAILED;
    }

    tasvir_init_rpc();

    if (tasvir_init_root(core, type)) {
        fprintf(stderr, "tasvir_init: tasvir_init_root failed\n");
        return MAP_FAILED;
    }

    if (tasvir_init_node()) {
        fprintf(stderr, "tasvir_init: tasvir_init_node failed\n");
        return MAP_FAILED;
    }

    this_instance = tasvir_init_instance(core, type);
    if (!this_instance) {
        fprintf(stderr, "tasvir_init: tasvir_init_instance failed\n");
        return MAP_FAILED;
    }

    // FIXME: backfill instance ptr
    if (type == TASVIR_INSTANCE_TYPE_ROOT) {
        root_desc->owner = this_instance;
    }
    if (is_tasvir_process) {
        node_desc->owner = this_instance;
    }

    return root_desc;
}

/*
static inline int
tasvir_testz_512(void *data, size_t len) {
    // TODO: assumes AVX512
    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        __m512i v = _mm512_loadu_si512(&data[i]);
        if (!_mm_testz_si512(v, v))
            return 0;
    }
    for (; i + 32 <= len; i += 32) {
        __m256i v = _mm256_loadu_si256(&data[i]);
        if (!_mm_testz_si256(v, v))
            return 0;
    }
    for (; i + 16 <= len; i += 16) {
        __m128i v = _mm_loadu_si128(&data[i]);
        if (!_mm_testz_si128(v, v))
            return 0;
    }
    for (; i < size; ++i) {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}
*/

/* is to be executed by the root */
static inline tasvir_area_desc *
tasvir_new2(tasvir_area_desc *pd, tasvir_instance *owner, uint8_t type, tasvir_str_static name, size_t len,
            uint64_t stale_us, int nr_areas_max) {
    len = ROUND_UP(len, PAGE_SIZE);
    assert(!pd || pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(len % TASVIR_LOG_GRAN == 0);
    assert(sizeof(name) == TASVIR_STRLEN_MAX);
    if (!owner)
        owner = this_instance;

    uint64_t time_us;
    void *addr = NULL, *addr_ret = NULL;
    bool is_local = !pd || (pd->owner == this_instance);
    tasvir_area_desc *d = NULL, *d_prev = NULL;
    tasvir_container *c = NULL;

    fprintf(stderr, "tasvir_new: is_local=%d pd=%p owner=%p type=%d name=%s len=%lu stale_us=%lu nr_areas_max=%d\n",
            is_local, pd, owner, type, name.str, len, stale_us, nr_areas_max);
    // initialize area descriptor
    if (pd) {
        if (is_local) {
            tasvir_container *c = (tasvir_container *)pd->h->data;
            assert(c->nr_areas < c->nr_areas_max);

            d = &c->descs[c->nr_areas];
            d_prev = c->nr_areas > 0 ? &c->descs[c->nr_areas - 1] : NULL;
            if (d_prev) {
                addr = (tasvir_area_header *)((uintptr_t)d_prev->h + d_prev->len);
            } else {
                addr = (tasvir_area_header *)((uintptr_t)c->descs + c->nr_areas_max * sizeof(tasvir_area_desc));
            }
            /* printf("nr_areas=%d %p (%p + %lu) == %p (%p + %lu) <= %p (%p + %lu)\n", c->nr_areas, (uintptr_t)d->h +
               len,
               d->h, len / 1000000, d_prev ? (uintptr_t)d_prev->h + d_prev->len : 0, d_prev ? d_prev->h : 0,
               d_prev ? d_prev->len / 1000000 : 0, (uintptr_t)pd->h + pd->len, pd->h, pd->len / 1000000; */
            assert((uintptr_t)addr + len <= (uintptr_t)pd->h + pd->len);
            c->nr_areas++;
        } else {
            d = tasvir_rpc_sync(10000, (tasvir_fnptr)&tasvir_new2_rpc, pd, owner, type, name, len, stale_us,
                                nr_areas_max);
        }
    } else {
        d = root_desc;
        addr = (void *)TASVIR_ROOT_DESC_ADDR;
    }

    if (is_local) {
        if (type == TASVIR_AREA_TYPE_CONTAINER) {
            int fd = shm_open(name.str, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd == -1) {
                fprintf(stderr, "tasvir_new: shm_open failed (%s)\n", strerror(errno));
                return MAP_FAILED;
            }

            if (ftruncate(fd, len)) {
                fprintf(stderr, "tasvir_new: ftruncate failed (%s)\n", strerror(errno));
                return MAP_FAILED;
            }

            addr_ret = mmap(addr, len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, fd, 0);
            fflush(stdout);
            if (addr_ret == MAP_FAILED) {
                fprintf(stderr, "tasvir_new: mmap failed (%s)\n", strerror(errno));
                return MAP_FAILED;
            } else if (addr != addr_ret) {
                fprintf(stderr, "tasvir_new: mmap address mismatch (%p != %p)\n", addr_ret, (void *)d->h);
                return MAP_FAILED;
            }
            close(fd);
        }

        time_us = this_node ? tasvir_gettime_us() : tasvir_gettime_us_pre();
        d->h = d == root_desc ? (void *)TASVIR_ROOT_AREA_ADDR : addr;
        d->pd = pd;
        d->len = len;
        d->type = type;
        d->owner = this_instance;
        strncpy(d->name, name.str, sizeof(tasvir_str));
        d->h->d = d;
        d->h->version = 1;
        d->h->stale_us = stale_us;
        d->h->update_us = time_us;
        d->h->boot_us = time_us;
        d->h->active = true;
        d->h->sync = true;
        if (type == TASVIR_AREA_TYPE_CONTAINER) {
            c = (tasvir_container *)d->h->data;
            c->nr_areas = 0;
            c->nr_areas_max = nr_areas_max;
        }
    }

    fprintf(stderr, "tasvir_new: name=%s len=%lu h=%p\n", name.str, len, (void *)d->h);

    return d;
}

tasvir_area_desc *
tasvir_new(tasvir_area_desc *pd, tasvir_instance *owner, uint8_t type, char *name, size_t len, uint64_t stale_us,
           int nr_areas_max) {
    tasvir_str_static name2;
    strncpy(name2.str, name, sizeof(tasvir_str));
    return tasvir_new2(pd, owner, type, name2, len, stale_us, nr_areas_max);
}

int
tasvir_delete(tasvir_area_desc *d) {
    assert(d->pd);
    bool is_local = d->pd->owner == this_instance;
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);

    tasvir_str name;
    strncpy(name, d->name, sizeof(tasvir_str));

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        if (munmap(d->h, d->len)) {
            fprintf(stderr, "tasvir_delete: munmap failed (%s)\n", strerror(errno));
            return -1;
        }
        if (shm_unlink(name)) {
            fprintf(stderr, "tasvir_delete: shm_unlink failed (%s)\n", strerror(errno));
            return -1;
        }
    }

    if (is_local) {
        d->h->active = false;
    } else {
        return *(int *)tasvir_rpc_sync(10000, (tasvir_fnptr)&tasvir_delete_rpc, d);
    }

    return 0;
}

tasvir_area_desc *
tasvir_attach(tasvir_area_desc *pd, char *name) {
    void *addr;
    int i, fd;
    struct stat fd_stat;
    tasvir_area_desc dummy, *d = NULL;
    tasvir_container *c;

    if (strncmp(name, "root", sizeof(tasvir_str)) == 0) {
        assert(!pd);
        d = &dummy;
        d->pd = NULL;
        d->h = (tasvir_area_header *)TASVIR_ROOT_DESC_ADDR;
        d->len = TASVIR_SIZE_WHOLE;
        d->type = TASVIR_AREA_TYPE_CONTAINER;
        d->owner = NULL;  // FIXME: backfill owner at the end
        strncpy(d->name, name, sizeof(tasvir_str));
    } else {
        assert(pd && pd->type == TASVIR_AREA_TYPE_CONTAINER);

        c = (tasvir_container *)pd->h->data;

        assert(c->nr_areas <= c->nr_areas_max);
        for (i = 0; i < c->nr_areas; i++) {
            if (strncmp(c->descs[i].name, name, sizeof(tasvir_str)) == 0) {
                d = &c->descs[i];
                break;
            }
        }
    }

    if (d == NULL) {
        fprintf(stderr, "tasvir_attach: could not find area %s under %s\n", name, pd->name);
        return MAP_FAILED;
    }

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        fd = shm_open(name, O_RDWR, 0);
        if (fd == -1) {
            fprintf(stderr, "tasvir_attach: shm_open failed (%s)\n", strerror(errno));
            return MAP_FAILED;
        }

        if (fstat(fd, &fd_stat)) {
            fprintf(stderr, "tasvir_attach: fstat failed (%s)\n", strerror(errno));
            return MAP_FAILED;
        }
        assert(fd_stat.st_size > 0 && (uint64_t)fd_stat.st_size == d->len);

        if (pd && munmap(d->h, d->len)) {
            fprintf(stderr, "tasvir_attach: munmap failed (%s)\n", strerror(errno));
            return MAP_FAILED;
        }

        addr = mmap(d->h, d->len, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
            fprintf(stderr, "tasvir_attach: mmap failed (%s)\n", strerror(errno));
            return MAP_FAILED;
        } else if (addr != d->h) {
            fprintf(stderr, "tasvir_attach: mmap address mismatch (%p != %p)\n", addr, (void *)d->h);
            return MAP_FAILED;
        }

        close(fd);
    }

    if (strncmp(name, "root", sizeof(tasvir_str)) == 0) {
        d = root_desc;
    }

    fprintf(stderr, "tasvir_attach: name=%s len=%lu h=%p\n", name, d->len, (void *)d->h);

    return d;
}

int
tasvir_detach(tasvir_area_desc *d) {
    assert(d->pd);
    assert(d->pd->type == TASVIR_AREA_TYPE_CONTAINER);
    assert(d->pd->owner != this_instance);

    tasvir_str name;
    strncpy(name, d->name, sizeof(tasvir_str));

    if (d->type == TASVIR_AREA_TYPE_CONTAINER) {
        if (munmap(d->h, d->len)) {
            fprintf(stderr, "tasvir_detach: munmap failed (%s)\n", strerror(errno));
            return -1;
        }
        if (shm_unlink(name)) {
            fprintf(stderr, "tasvir_detach: shm_unlink failed (%s)\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

/* sync */

int
tasvir_sync() {
    uint64_t time_us = tasvir_gettime_us();
    if (is_tasvir_process) {
        root_desc->h->update_us = time_us;
        node_desc->h->update_us = time_us;
    } else {
    }
    return 0;
}

/* RPC */

static tasvir_rpc_status *
tasvir_vrpc_async(tasvir_fnptr fnptr, bool do_free, va_list argp) {
    int i;
    uint8_t *ptr;
    tasvir_msg_rpc *msg;
    tasvir_rpc_status *status;
    struct rte_ring *ring =
        this_instance ? this_local->rings[this_instance->id.port_id].tx : this_local->rings_discovery.tx;
    if (rte_mempool_get(this_local->mp, (void **)&msg)) {
        fprintf(stderr, "tasvir_vrpc_async: rte_mempool_get failed\n");
        return NULL;
    }
    assert(msg);

    tasvir_fn_info *fni;
    HASH_FIND(h_fnptr, ht_fnptr, &fnptr, sizeof(fnptr), fni);
    assert(fni);

    msg->h.id = tasvir_msg_id++;
    msg->h.type = TASVIR_MSG_TYPE_RPC_REQUEST;
    msg->fid = fni->fid;
    ptr = msg->data + ROUND_UP(fni->ret_len, sizeof(int));

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
            default:
                abort();
                break;
            }
        }
        msg->arg_ptrs[i] = ptr;
        ptr += ROUND_UP(fni->arg_lens[i], sizeof(int));
    }

    if (rte_ring_sp_enqueue(ring, msg) != 0) {
        fprintf(stderr, "tasvir_vrpc_async: rte_ring_sp_enqueue failed\n");
        rte_mempool_put(this_local->mp, (void *)msg);
        return NULL;
    }
    fprintf(stderr, "rpc call id=%d fid=%d name=%s argc=%d\n", msg->h.id, msg->fid, fni->name, fni->argc);

    status = &status_l[msg->h.id];
    // garbage collect a previous status
    if (status->do_free && status->response)
        rte_mempool_put(this_local->mp, (void *)status->response);
    status->id = msg->h.id;
    status->do_free = do_free;
    status->status = TASVIR_RPC_STATUS_PENDING;
    status->response = NULL;
    status->cb = NULL;

    return status;
}

tasvir_rpc_status *
tasvir_rpc_async(tasvir_fnptr fnptr, ...) {
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(fnptr, true, argp);
    va_end(argp);
    return status;
}

void *
tasvir_rpc_sync(uint64_t timeout_us, tasvir_fnptr fnptr, ...) {
    struct timespec ts = {0, 50000};
    va_list argp;
    va_start(argp, fnptr);
    tasvir_rpc_status *status = tasvir_vrpc_async(fnptr, false, argp);
    va_end(argp);
    while (status->status == TASVIR_RPC_STATUS_PENDING) {
        nanosleep(&ts, NULL);
        tasvir_rpc_serve();
    }
    // tasvir_sync();
    assert(status->status != TASVIR_RPC_STATUS_DONE || status->response);
    return status->status == TASVIR_RPC_STATUS_DONE ? *(void **)status->response->data : NULL;
}

int
tasvir_rpc_register(tasvir_fn_info *fni) {
    fn_infos[tasvir_nr_fn] = *fni;
    HASH_ADD(h_fid, ht_fid, fid, sizeof(fni->fid), &fn_infos[tasvir_nr_fn]);
    HASH_ADD(h_fnptr, ht_fnptr, fnptr, sizeof(fni->fnptr), &fn_infos[tasvir_nr_fn]);
    tasvir_nr_fn++;
    return 0;
}

static void
tasvir_rpc_serve_rp(tasvir_ring_pair *rp) {
    tasvir_fn_info *fni;
    tasvir_msg_rpc *msg;
    struct rte_ring *ring_rx = is_tasvir_process ? rp->tx : rp->rx;
    struct rte_ring *ring_tx = is_tasvir_process ? rp->rx : rp->tx;

    if (rte_ring_sc_dequeue(ring_rx, (void **)&msg) != 0 || !msg) {
        return;
    }

    assert(msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST || msg->h.type == TASVIR_MSG_TYPE_RPC_RESPONSE);
    HASH_FIND(h_fid, ht_fid, &msg->fid, sizeof(msg->fid), fni);
    assert(fni);
    fprintf(stderr, "serving rpc: type=%d id=%d fid=%d name=%s argc=%d\n", msg->h.type, msg->h.id, msg->fid, fni->name,
            fni->argc);

    if (msg->h.type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        fni->fnptr(msg->data, msg->arg_ptrs);
        msg->h.type = TASVIR_MSG_TYPE_RPC_RESPONSE;
        if (rte_ring_sp_enqueue(ring_tx, msg) != 0) {
            fprintf(stderr, "tasvir_rpc_serve: rte_ring_sp_enqueue failed\n");
            rte_mempool_put(this_local->mp, (void *)msg);
            return;
        }
    } else if (msg->h.type == TASVIR_MSG_TYPE_RPC_RESPONSE) {
        HASH_FIND(h_fid, ht_fid, &msg->fid, sizeof(msg->fid), fni);
        assert(fni);
        assert(msg->h.id < TASVIR_NR_RPC_MSG);
        tasvir_rpc_status *status = &status_l[msg->h.id];
        status->status = TASVIR_RPC_STATUS_DONE;
        if (status->do_free)
            rte_mempool_put(this_local->mp, (void *)msg);
        else
            status->response = msg;
    }
}

void
tasvir_rpc_serve() {
    if (is_tasvir_process) {
        tasvir_rpc_serve_rp(&this_local->rings_discovery);
        for (int i = 1; i < TASVIR_NR_INSTANCES_LOCAL; i++) {
            if (this_node->instances[i].active)
                tasvir_rpc_serve_rp(&this_local->rings[i]);
        }
    } else {
        if (this_instance)
            tasvir_rpc_serve_rp(&this_local->rings[this_instance->id.port_id]);
        else
            tasvir_rpc_serve_rp(&this_local->rings_discovery);
    }
}

/* write tracking */

void
logop(void *addr, size_t len) {
    void *shadow_addr = (void *)((uintptr_t)addr >> 9);
    int shadow_bit = ((uintptr_t)addr >> 6) % 8;
    printf("write @ %p (%zu bytes)\t|\t", addr, len);
    printf("shadow @ %p (bit %d)\n", shadow_addr, shadow_bit);
}
