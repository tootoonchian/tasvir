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

#define TASVIR_ALIGNMENT (4 * 1024)
#define ALIGNED_LENGTH(x) (1 + ((x - 1) | (TASVIR_ALIGNMENT - 1)))
#define TASVIR_AREA_BYTES (32 * 1024 * 1024)
#define TASVIR_LOG_GRAN (1 << 9)  // 1 bit per cacheline
#define TASVIR_RING_SIZE (256)

static uint64_t tsc_hz = 0;
static tasvir_meta *daemon_meta = NULL;
static tasvir_node *my_node;
static tasvir_instance my_instance;

static inline uint64_t
tasvir_gettime_us(void) {
    return 1E6 * rte_rdtsc() / tsc_hz;
}

static int
tasvir_register_instance(tasvir_meta *meta) {
    /* msg to meta owner */
    return 0;
}

static int
tasvir_init_dpdk(int core, bool daemon) {
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
    argv[argc++] = "0";
    argv[argc++] = "--socket-mem";
    argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
    argv[argc++] = daemon ? "primary" : "secondary";
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        fprintf(stderr, "tasvir_init_dpdk: rte_eal_init failed\n");
        return -1;
    }
    return 0;
}

int
tasvir_init(int core) {
    if (tasvir_init_dpdk(core, false)) {
        fprintf(stderr, "tasvir_init: dpdk init failed\n");
        return -1;
    }

    daemon_meta = tasvir_attach("tasvir_daemon");
    if (daemon_meta == MAP_FAILED) {
        fprintf(stderr, "tasvir_init: daemon map failed\n");
        return -1;
    }

    my_node = daemon_meta->data_rw.addr;
    assert(daemon_meta->data_rw.len >= sizeof(tasvir_node));
    tsc_hz = my_node->tsc_hz;
    uint64_t time_us = tasvir_gettime_us();
    printf("time_us=%lu update_us=%lu stale_us=%lu < %u\n", time_us, daemon_meta->update_us,
           time_us - daemon_meta->update_us, daemon_meta->stale_us);
    if (!daemon_meta->active) {
        fprintf(stderr, "tasvir_init: daemon is inactive\n");
        return -1;
    } else if (time_us > daemon_meta->update_us && time_us - daemon_meta->update_us > daemon_meta->stale_us) {
        fprintf(stderr, "tasvir_init: daemon has been stale for %lu us (> %u)\n", time_us - daemon_meta->update_us,
                daemon_meta->stale_us);
        return -1;
    }

    uuid_generate(my_instance.uuid);
    memcpy(my_instance.ethaddr, my_node->ethaddr, sizeof(my_instance.ethaddr));
    my_instance.stale_us = 5000;
    my_instance.update_us = time_us;
    my_instance.active = true;

    return 0;
}

int
tasvir_init_daemon(int core) {
    if (tasvir_init_dpdk(core, true)) {
        fprintf(stderr, "tasvir_init_daemon: dpdk init failed\n");
        return -1;
    }

    tsc_hz = rte_get_tsc_hz();
    daemon_meta = tasvir_new("tasvir_daemon", sizeof(tasvir_node));

    if (daemon_meta == MAP_FAILED) {
        fprintf(stderr, "tasvir_init_daemon: map failed\n");
        return -1;
    }

    my_node = daemon_meta->data_rw.addr;
    assert(daemon_meta->data_rw.len >= sizeof(tasvir_node));
    my_node->tsc_hz = tsc_hz;
    my_node->boot_us = tasvir_gettime_us();
    uuid_generate(my_node->uuid);
    sscanf("68:05:ca:27:99:48", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &my_node->ethaddr[0], &my_node->ethaddr[1],
           &my_node->ethaddr[2], &my_node->ethaddr[3], &my_node->ethaddr[4], &my_node->ethaddr[5]);

    for (int i = 0; i < TASVIR_NR_AREA_INSTANCES; i++) {
        char tmp[32];
        sprintf(tmp, "tasvir_tx_%d", i);
        my_node->rings_local[i].tx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(i), RING_F_SP_ENQ | RING_F_SC_DEQ);
        sprintf(tmp, "tasvir_rx_%d", i);
        my_node->rings_local[i].rx =
            rte_ring_create(tmp, TASVIR_RING_SIZE, rte_lcore_to_socket_id(i), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    my_node->mp = rte_pktmbuf_pool_create("mempool", 16 * 1024, 256, 0, 2048 + RTE_PKTMBUF_HEADROOM, rte_socket_id());

    return 0;
}

/*
static inline int
tasvir_testz_512(void *data, size_t length) {
    // TODO: assumes AVX512
    size_t i = 0;
    for (; i + 64 <= length; i += 64) {
        __m512i v = _mm512_loadu_si512(&data[i]);
        if (!_mm_testz_si512(v, v))
            return 0;
    }
    for (; i + 32 <= length; i += 32) {
        __m256i v = _mm256_loadu_si256(&data[i]);
        if (!_mm_testz_si256(v, v))
            return 0;
    }
    for (; i + 16 <= length; i += 16) {
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

static int
tasvir_init_area(tasvir_meta *meta, int i) {
    assert(TASVIR_AREA_BYTES % TASVIR_LOG_GRAN == 0);
    tasvir_area *area = &meta->areas[i];
    area->active = false;
    area->version = 0;
    area->stale_us = 0;
    area->update_us = 0;
    area->shadow.addr = (void *)((uintptr_t)meta->shadow.addr + i * TASVIR_AREA_BYTES / TASVIR_LOG_GRAN);
    area->shadow.len = TASVIR_AREA_BYTES / TASVIR_LOG_GRAN;
    area->data_ro.addr = (void *)((uintptr_t)meta->data_ro.addr + i * TASVIR_AREA_BYTES);
    area->data_ro.len = TASVIR_AREA_BYTES;
    area->data_rw.addr = (void *)((uintptr_t)meta->data_rw.addr + i * TASVIR_AREA_BYTES);
    area->data_rw.len = TASVIR_AREA_BYTES;

    return 0;
}

tasvir_meta *
tasvir_new(const char *name, size_t length) {
    int i;
    // ensure proper alignment
    length = ALIGNED_LENGTH(length);
    size_t meta_len = ALIGNED_LENGTH(sizeof(tasvir_meta));
    size_t shadow_len = ALIGNED_LENGTH(length / TASVIR_LOG_GRAN);
    size_t total_len = meta_len + shadow_len + length * 2;
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "tasvir_new: shm_open failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }

    if (ftruncate(fd, total_len)) {
        fprintf(stderr, "tasvir_new: ftruncate failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }

    void *addr = mmap(NULL, total_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "tasvir_new: mmap failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }
    close(fd);

    tasvir_meta *meta = addr;
    memset(addr, 0, meta_len);
    meta->base.addr = addr;
    meta->base.len = total_len;
    meta->shadow.addr = meta->base.addr;
    meta->shadow.len = shadow_len;
    meta->data_ro.addr = (void *)((uintptr_t)meta->shadow.addr + meta->shadow.len);
    meta->data_ro.len = length;
    meta->data_rw.addr = (void *)((uintptr_t)meta->data_ro.addr + meta->data_ro.len);
    meta->data_rw.len = length;

    for (i = 0; i < TASVIR_NR_AREAS; i++) {
        if (tasvir_init_area(meta, i)) {
            fprintf(stderr, "tasvir_new: tasvir_init_area failed\n");
            return MAP_FAILED;
        }
    }

    strncpy(meta->name, name, TASVIR_STRLEN_MAX);
    meta->version = 1;
    meta->stale_us = 5000;
    meta->update_us = tasvir_gettime_us();
    meta->instances[0] = my_instance;
    meta->active = true;
    fprintf(stderr, "tasvir_new: total=%lu meta=%lu shadow=%lu datalen=%lu\n", total_len, meta_len, shadow_len, length);

    return meta;
}

int
tasvir_delete(const tasvir_meta *meta) {
    char name[TASVIR_STRLEN_MAX];
    strncpy(name, meta->name, TASVIR_STRLEN_MAX);
    if (munmap(meta->base.addr, meta->base.len)) {
        fprintf(stderr, "tasvir_delete: munmap failed (%s)\n", strerror(errno));
        return -1;
    }
    if (shm_unlink(name)) {
        fprintf(stderr, "tasvir_delete: shm_unlink failed (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

tasvir_meta *
tasvir_attach(const char *name) {
    tasvir_meta *meta;
    struct stat fd_stat;

    int fd = shm_open(name, O_RDWR, 0);
    if (fd == -1) {
        fprintf(stderr, "tasvir_attach: shm_open failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }

    if (fstat(fd, &fd_stat)) {
        fprintf(stderr, "tasvir_attach: fstat failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }
    assert(fd_stat.st_size > 0 && (uint64_t)fd_stat.st_size >= sizeof(tasvir_meta));

    void *addr = mmap(NULL, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "tasvir_attach: mmap failed (%s)\n", strerror(errno));
        return MAP_FAILED;
    }

    meta = addr;
    assert(fd_stat.st_size > 0 && (uint64_t)fd_stat.st_size == meta->base.len);

    if (meta->base.addr != addr) {
        addr = mremap(addr, meta->base.len, meta->base.len, MREMAP_FIXED | MREMAP_MAYMOVE, meta->base.addr);
        meta = addr;
        if (addr == MAP_FAILED) {
            fprintf(stderr, "tasvir_attach: mremap failed (%s)\n", strerror(errno));
            return MAP_FAILED;
        } else if (addr != meta->base.addr) {
            fprintf(stderr, "tasvir_attach: mremap address mismatch (%p != %p)\n", addr, meta->base.addr);
            return MAP_FAILED;
        }
    }
    close(fd);

    tasvir_register_instance(meta);

    return meta;
}

int
tasvir_detach(const tasvir_meta *meta) {
    return 0;
}

int
tasvir_sync(const tasvir_meta *meta) {
    return 0;
}

int
tasvir_sync_daemon() {
    uint64_t time_us = tasvir_gettime_us();
    daemon_meta->update_us = time_us;
    return 0;
}

tasvir_area *
tasvir_area_new(const tasvir_meta *meta, const char *name, uint32_t stale_us) {
    tasvir_area *area = NULL;
    // search for duplicates among active areas
    for (int i = 0; i < TASVIR_NR_AREAS; i++) {
        if (!meta->areas[i].active) {
            area = (tasvir_area *)&meta->areas[i];
        } else if (!strncmp(meta->areas[i].name, name, TASVIR_STRLEN_MAX)) {
            fprintf(stderr, "tasvir_area_new: %s already exists\n", name);
            return NULL;
        }
    }
    strncpy(area->name, name, TASVIR_STRLEN_MAX);
    area->active = true;
    area->version = 1;
    area->stale_us = stale_us;
    area->update_us = tasvir_gettime_us();

    return area;
}

int
tasvir_area_delete(tasvir_area *area) {
    if (!area->active)
        return -1;
    area->active = false;
    return 0;
}

tasvir_area *
tasvir_area_subscribe(const tasvir_meta *meta, const char *name) {
    return NULL;
}

int
tasvir_area_unsubscribe(const tasvir_area *area) {
    return 0;
}

void
logop(void *addr, size_t len) {
    void *shadow_addr = (void *)((uintptr_t)addr >> 9);
    int shadow_bit = ((uintptr_t)addr >> 6) % 8;
    printf("write @ %p (%zu bytes)\t|\t", addr, len);
    printf("shadow @ %p (bit %d)\n", shadow_addr, shadow_bit);
}
