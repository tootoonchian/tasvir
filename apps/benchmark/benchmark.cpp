#include <cpuid.h>
#include <fcntl.h>
#include <getopt.h>
#include <immintrin.h>
#include <rte_cycles.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <random>
#include <type_traits>

#include <tasvir/tasvir.h>
#include <tasvir/array.hpp>

using namespace std;

#ifndef RNDCNT
#define RNDCNT (64 * 1024)
#endif

#define EXPAND_ARGID(argid)                      \
    constexpr bool do_stream = (argid >> 3) % 2; \
    constexpr bool random = (argid >> 2) % 2;    \
    constexpr bool do_log = (argid >> 1) % 2;    \
    constexpr bool do_service = (argid >> 0) % 2;

struct benchmark_cfg {
    void *data;
    size_t area_len;
    uint8_t *rand_arr;
    int stride;

    int core;
    int wid;
    int nr_workers;
    int nr_writers;
    int nr_rounds;

    uint64_t sync_int_us;
    uint64_t sync_ext_us;

    long duration_ms;
    int service_us;

    struct {
        uint64_t nr_writes;
        uint64_t nr_writes_per_service;
    } this_run;

    struct {
        uint64_t nr_syncs;
        uint64_t nr_sync_fails;
        uint64_t nr_writes;
        uint64_t runtime_1m_us;
        uint64_t runtime_us;
        uint64_t barr_1m_us;
        uint64_t barr_us;
        uint64_t sync_1m_us;
        uint64_t sync_us;
        uint64_t sync_bytes;
        uint64_t write_xput_mbps;
    } stats[2][2][2][2];
};

static inline uint64_t rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

static inline uint64_t xoroshiro128plus() {
    static uint64_t s[2] = {0x03535b53690c, 0xb8cca719e380};
    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = s0 + s1;

    s1 ^= s0;
    s[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);  // a, b
    s[1] = rotl(s1, 37);                    // c

    return result;
}

static inline uint64_t xorshift128plus(void) {
    static uint64_t s[2] = {0x03535b53690c, 0xb8cca719e380};
    uint64_t x = s[0];
    const uint64_t y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}

template <bool random>
static inline uint64_t next_masked(const uint64_t mask, int stride) {
    if (random) {
        return xoroshiro128plus() & mask;
    } else {
        static uint64_t s = 0;
        s += stride;
        return s & mask;
    }
}

static inline long next_pow2(long x) { return 1UL << (64 - __builtin_clzl((x - 1) | 1)); }

static inline double diff_pos(uint64_t a, uint64_t b) { return a > b ? a - b : 0; }

static inline void cpuid(unsigned int &family, unsigned int &model) {
    int a, b, c, d;
    __cpuid(1, a, b, c, d);
    /*
        stepping : 4;
        model : 4;
        family : 4;
        processor_type : 2;
        reserved : 2;
        extended_model : 4;
        extended_family : 8;
    */
    family = (a >> 8) & 0xf;
    family += (a >> 20) & 0xff;
    model = (a >> 4) & 0xf;
    model += ((a >> 16) & 0xf) << 4;

    if (family != 6) {
        fprintf(stderr, "Only CPU family 6 is supported.\n");
        abort();
    }
}

static inline void store_novec(void *dst, void *src, size_t len) {
    void *dst_end = (void *)((uintptr_t)dst + len);
    do {
        *(uint64_t *)dst = *(uint64_t *)src;
        dst = (uint8_t *)dst + 8;
        src = (uint8_t *)src + 8;

    } while (dst < dst_end);
}

template <bool random, int n>
static inline typename enable_if<n == 0, void>::type next_read(const void *, uint64_t, int) {}

template <bool random, int n>
static inline typename enable_if<n != 0, void>::type next_read(const void *s, uint64_t mask, int stride) {
    size_t offset = next_masked<random>(mask, stride);
    s = (uint8_t *)s + offset;

    // volatile tasvir_stream_vec_rep(d, s, stride);

    next_read<random, n - 1>(s, mask, stride);
}

template <bool do_log, bool do_stream, bool random, int n>
static inline typename enable_if<n == 0, void>::type next_write(void *, const void *, uint64_t, int) {}

template <bool do_log, bool do_stream, bool random, int n>
static inline typename enable_if<n != 0, void>::type next_write(void *d, const void *s, uint64_t mask, int stride) {
    size_t offset = next_masked<random>(mask, stride);
    s = (uint8_t *)s + (offset & (RNDCNT - 1));
    d = (uint8_t *)d + offset;

    if (do_stream) {
        tasvir_stream_vec_rep(d, s, stride);
    } else {
        tasvir_store_vec_rep(d, s, stride);
    }

    next_write<do_log, do_stream, random, n - 1>(d, s, mask, stride);

    if (do_log)
        tasvir_log(d, stride);

    if (false) {
        // tasvir_log2(d, stride);
        // tasvir_log_t *log_addr = (tasvir_log_t *)((uintptr_t)tasvir_data2logunit(d) & ~31L);
        // _mm_stream_pi((__m64 *)TASVIR_ADDR_LOG, (__m64)0UL);
        // *(uint64_t *)TASVIR_ADDR_LOG = n;
        // *log_addr |= 55UL;
        // _mm_prefetch(log0, _MM_HINT_NTA);
        tasvir_log_t *log0 = tasvir_data2logunit(d);
        uint64_t idx0 = tasvir_data2logbit(d);
        uint64_t mask0 = ~0UL >> idx0;

        const void *d1 = (uint8_t *)d + stride;
        tasvir_log_t *log1 = tasvir_data2logunit(d1);
        uint64_t idx1 = tasvir_data2logbit(d1);
        uint64_t mask1 = ((1L << 63) >> idx1);

        if (likely(log0 == log1)) {
            *log0 |= (mask0 & mask1);
        } else {
            *log0 |= mask0;
            do {
                *(++log0) = ~0UL;
            } while (log0 < log1);
            *log1 |= mask1;
        }
    }

    /* roughly 18 instructions: 4.5 cycles/write */
    if (false) {
        tasvir_log_t *log = tasvir_data2logunit(d);
        stride += ((uintptr_t)d % TASVIR_LOG_GRANULARITY_BYTES) + TASVIR_LOG_GRANULARITY_BYTES - 1;
        uint64_t idx = tasvir_data2logbit(d);
        size_t nbits = stride >> TASVIR_SHIFT_BIT;
        if (likely(idx + nbits <= 64)) {
            *log |= ((uint64_t)((1L << 63) >> (nbits - 1)) >> idx);
        } else {
            *(log++) |= ~0UL >> idx;
            nbits += idx;
            while ((nbits -= 64) > 64) {
                *(log++) = ~0UL;
            }
            *log |= (1L << 63) >> (nbits - 1);
        }
    }
}

static void flush_cache() {
    int fd = open("/lib/modules/4.19.0-1-amd64/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (fd) {
        syscall(__NR_finit_module, fd, "", 0);
        syscall(__NR_delete_module, "wbinvd", 0);
        close(fd);
    }
}

template <int round, int argid, int write_batch>
typename enable_if<round == 0, void>::type experiment(benchmark_cfg *cfg) {
    EXPAND_ARGID(argid);

    auto &s = cfg->stats[do_stream][random][do_log][do_service];
    s.nr_syncs /= cfg->nr_rounds;
    s.nr_sync_fails /= cfg->nr_rounds;
    s.nr_writes /= cfg->nr_rounds;
    s.runtime_us /= cfg->nr_rounds;
    s.barr_us /= cfg->nr_rounds;
    s.sync_us /= cfg->nr_rounds;
    s.sync_bytes /= cfg->nr_rounds;
    s.runtime_1m_us = 1E6 * s.runtime_us / s.nr_writes;
    s.barr_1m_us = 1E6 * s.barr_us / s.nr_writes;
    s.sync_1m_us = 1E6 * s.sync_us / s.nr_writes;
    s.write_xput_mbps = cfg->stride * s.nr_writes / s.runtime_us;

    printf("\n");
}

template <int round, int argid, int write_batch>
typename enable_if<argid == -1, void>::type experiment(benchmark_cfg *) {}

template <int round, int argid, int write_batch>
typename enable_if<round != 0 && argid >= 0, void>::type __attribute__((noinline)) experiment(benchmark_cfg *cfg) {
    EXPAND_ARGID(argid);

    static uint64_t mask = (cfg->area_len - 1) & ~(TASVIR_VEC_BYTES - 1);
    uint64_t t;

    /* warmup and calibration */
    if (round == cfg->nr_rounds && do_log == 1 && do_service == 1) {
        int nr_test_writes = 1000 * 1000;
        flush_cache();
        t = tasvir_rdtsc();
        for (int i = 0; i < nr_test_writes; i += write_batch)
            next_write<do_log, do_stream, random, write_batch>(cfg->data, cfg->rand_arr, mask, cfg->stride);
        t = tasvir_tsc2usec(tasvir_rdtsc() - t);

        cfg->this_run.nr_writes = 1000 * nr_test_writes * cfg->duration_ms / (double)t;
        cfg->this_run.nr_writes_per_service = nr_test_writes * cfg->service_us / (double)t;
    }

    printf("round=%d stream=%d random=%d log=%d service=%d : ", round, do_stream, random, do_log, do_service);

    tasvir_service_wait(1000 * 1000);
    flush_cache();
    asm volatile("" ::: "memory");
    tasvir_stats_reset();
    t = tasvir_rdtsc();
    asm volatile("" ::: "memory");

    for (uint64_t i = 0; i < cfg->this_run.nr_writes; i += cfg->this_run.nr_writes_per_service) {
        for (uint64_t j = 0; j < cfg->this_run.nr_writes_per_service; j += write_batch)
            next_write<do_log, do_stream, random, write_batch>(cfg->data, cfg->rand_arr, mask, cfg->stride);

        if (do_service)
            tasvir_service();
    }

    asm volatile("" ::: "memory");
    t = tasvir_tsc2usec(tasvir_rdtsc() - t);
    tasvir_stats ts = tasvir_stats_get();
    asm volatile("" ::: "memory");
    printf("runtime_ms=%5ld nr_writes_k=%6ld sync_success=%5ld sync_failure=%5ld sync_time_ms=%5ld sync_size_kb=%8ld\n",
           t / 1000, cfg->this_run.nr_writes / 1000, ts.success, ts.failure, ts.sync_us / 1000, ts.sync_bytes / 1000);

    auto &s = cfg->stats[do_stream][random][do_log][do_service];
    s.nr_syncs += ts.success;
    s.nr_sync_fails += ts.failure;
    s.nr_writes += cfg->this_run.nr_writes;
    s.runtime_us += t;
    s.barr_us += ts.sync_barrier_us;
    s.sync_us += ts.sync_us;
    s.sync_bytes += ts.sync_bytes;

    experiment<round - 1, argid, write_batch>(cfg);
    if (round == cfg->nr_rounds)
        experiment<round, argid - 1, write_batch>(cfg);
}

void service_loop() {
    while (1) {
        tasvir_service();
        rte_delay_us_block(1);
    }
}

int init(benchmark_cfg *cfg) {
    cfg->rand_arr = (uint8_t *)aligned_alloc(TASVIR_VEC_BYTES, RNDCNT * 2);
    for (size_t i = 0; i < RNDCNT; i += 8)
        *(uint64_t *)&cfg->rand_arr[i] = xorshift128plus();

    tasvir_area_desc *root_desc = tasvir_init(cfg->core);
    if (!root_desc) {
        fprintf(stderr, "tasvir_init failed\n");
        return -1;
    }

    tasvir_area_desc *d = NULL;
    for (int i = 0; i < cfg->nr_workers; i += cfg->nr_workers / cfg->nr_writers) {
        if (cfg->wid == i) {
            tasvir_area_desc param = {};
            param.pd = root_desc;
            param.len = cfg->area_len + 2 * TASVIR_VEC_BYTES;
            param.sync_int_us = cfg->sync_int_us;
            param.sync_ext_us = cfg->sync_ext_us;
            snprintf(param.name, sizeof(param.name), "benchmark-%d", cfg->wid);
            d = tasvir_new(param);
            if (!d) {
                fprintf(stderr, "tasvir_new %s failed\n", param.name);
                return -1;
            }
            memset(tasvir_data(d), 0, d->len); /* to ensure reservation */
        } else {
            tasvir_str name;
            snprintf(name, sizeof(name), "benchmark-%d", i);
            if (tasvir_attach_wait(root_desc, name, NULL, false, 5 * 1000 * 1000) == NULL) {
                fprintf(stderr, "tasvir_attach %s failed\n", name);
                return -1;
            }
        }
    }

    if (d) {
        auto alignment = TASVIR_VEC_BYTES;
        cfg->data = (uint8_t *)(((uintptr_t)tasvir_data(d) + alignment - 1) & ~(alignment - 1));
        return 0;
    } else {
        service_loop();
        return -1;
    }
}

void usage(char *exec) {
    fprintf(stderr,
            "Usage: %s --wid wid --core core --nr_workers nr_workers --nr_writers nr_writers --duration_ms duration_ms "
            "--service_us service_us --area_len area_len_bytes --stride stride --sync_int_us sync_int_us "
            "--sync_ext_us sync_ext_us\n",
            exec);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    benchmark_cfg cfg = {};

    while (1) {
        static struct option long_options[] = {{"core", required_argument, 0, 'c'},
                                               {"sync_int_us", required_argument, 0, 'x'},
                                               {"sync_ext_us", required_argument, 0, 'X'},
                                               {"wid", required_argument, 0, 'i'},
                                               {"nr_workers", required_argument, 0, 'n'},
                                               {"nr_writers", required_argument, 0, 'w'},
                                               {"duration_ms", required_argument, 0, 'd'},
                                               {"service_us", required_argument, 0, 's'},
                                               {"area_len", required_argument, 0, 'b'},
                                               {"stride", required_argument, 0, 'l'},
                                               {"help", no_argument, 0, 'h'},
                                               {0, 0, 0, 0}};
        int c = getopt_long(argc, argv, "c:x:X:i:n:w:d:s:b:l:h", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            cfg.core = atoi(optarg);
            break;
        case 'x':
            cfg.sync_int_us = atoi(optarg);
            break;
        case 'X':
            cfg.sync_ext_us = atoi(optarg);
            break;
        case 'i':
            cfg.wid = atoi(optarg);
            break;
        case 'n':
            cfg.nr_workers = atoi(optarg);
            break;
        case 'w':
            cfg.nr_writers = atoi(optarg);
            break;
        case 'd':
            cfg.duration_ms = atol(optarg);
            break;
        case 's':
            cfg.service_us = atoi(optarg);
            break;
        case 'b':
            cfg.area_len = next_pow2(atol(optarg));
            break;
        case 'l':
            cfg.stride = (atoi(optarg) + TASVIR_VEC_BYTES - 1) & ~(TASVIR_VEC_BYTES - 1);
            break;
        case 'h':
            usage(argv[0]);
            break;
        default:
            fprintf(stderr, "Unrecognized option 0%o\n", c);
            usage(argv[0]);
        }
    }

    constexpr int nr_rounds = 3;
    constexpr int write_batch = 1;
    cfg.nr_rounds = nr_rounds;
    unsigned int family, model;
    cpuid(family, model);

    if (init(&cfg) != 0)
        return -1;

    printf("cmdline: ");
    for (int i = 0; i < argc; i++)
        printf("%s ", argv[i]);
    printf(
        "\nRUNS cpu=%d-%d wid=%d core=%d nr_workers=%d nr_writers=%d service_us=%d "
        "area_len_kb=%lu stride_b=%d sync_int_us=%lu sync_ext_us=%lu\n",
        family, model, cfg.wid, cfg.core, cfg.nr_workers, cfg.nr_writers, cfg.service_us, cfg.area_len / 1024,
        cfg.stride, cfg.sync_int_us, cfg.sync_ext_us);

    experiment<nr_rounds, 7, write_batch>(&cfg);

    for (int do_stream = 0; do_stream >= 0; do_stream--) {
        for (int random = 1; random >= 0; random--) {
            double overhead_isync_noop =
                100. * cfg.stats[do_stream][random][0][1].sync_1m_us / cfg.stats[do_stream][random][0][0].runtime_1m_us;
            double overhead_isync_full =
                100. * cfg.stats[do_stream][random][1][1].sync_1m_us / cfg.stats[do_stream][random][0][0].runtime_1m_us;

            double overhead_log = 100. *
                                  diff_pos(cfg.stats[do_stream][random][1][0].runtime_1m_us,
                                           cfg.stats[do_stream][random][0][0].runtime_1m_us) /
                                  cfg.stats[do_stream][random][0][0].runtime_1m_us;
            double overhead_noop = 100. *
                                   diff_pos(cfg.stats[do_stream][random][0][1].runtime_1m_us,
                                            cfg.stats[do_stream][random][0][0].runtime_1m_us) /
                                   cfg.stats[do_stream][random][0][0].runtime_1m_us;
            double overhead_full = 100. *
                                   diff_pos(cfg.stats[do_stream][random][1][1].runtime_1m_us,
                                            cfg.stats[do_stream][random][0][0].runtime_1m_us) /
                                   cfg.stats[do_stream][random][0][0].runtime_1m_us;

            double overhead_serv = overhead_noop - overhead_isync_noop;
            if (overhead_serv < 0)
                overhead_serv = 0;
            double overhead_direct = overhead_log + overhead_isync_full + overhead_serv;
            double overhead_indirect = overhead_full - overhead_direct;

            double isync_xput_mbps =
                cfg.stats[do_stream][random][1][1].sync_bytes / cfg.stats[do_stream][random][1][1].sync_us;
            double isync_xput_per_core_mbps = isync_xput_mbps / (cfg.nr_workers + 1);
            double isync_xput_per_call_mbps = isync_xput_mbps / cfg.stats[do_stream][random][1][1].nr_syncs;
            double isync_write_pcnt = 100. * cfg.stats[do_stream][random][1][1].sync_bytes /
                                      (cfg.stats[do_stream][random][1][1].nr_writes * cfg.stride);
            double isync_time_barr_per_call_us =
                (double)cfg.stats[do_stream][random][0][1].barr_us / cfg.stats[do_stream][random][0][1].nr_syncs;
            double isync_time_noop_per_call_us =
                (double)cfg.stats[do_stream][random][0][1].sync_us / cfg.stats[do_stream][random][0][1].nr_syncs;
            double isync_time_full_per_call_us =
                (double)cfg.stats[do_stream][random][1][1].sync_us / cfg.stats[do_stream][random][1][1].nr_syncs;

            printf(
                "RESULTS cpu=%d-%d wid=%d core=%d nr_workers=%d nr_writers=%d service_us=%d "
                "area_len_kb=%lu stride_b=%d sync_int_us=%lu sync_ext_us=%lu stream=%d random=%d\n",
                family, model, cfg.wid, cfg.core, cfg.nr_workers, cfg.nr_writers, cfg.service_us, cfg.area_len / 1024,
                cfg.stride, cfg.sync_int_us, cfg.sync_ext_us, do_stream, random);

            for (int do_log = 0; do_log <= 1; do_log++)
                for (int do_service = 0; do_service <= 1; do_service++)
                    printf("          runtime_1m_l%ds%d_us=%8lu\n", do_log, do_service,
                           cfg.stats[do_stream][random][do_log][do_service].runtime_1m_us);

            for (int do_log = 0; do_log <= 1; do_log++)
                for (int do_service = 0; do_service <= 1; do_service++)
                    printf("        write_xput_l%ds%d_mbps=%8lu\n", do_log, do_service,
                           cfg.stats[do_stream][random][do_log][do_service].write_xput_mbps);

            printf("%28s=%8.2f\n", "isync_write_pct", isync_write_pcnt);
            printf("%28s=%8.2f\n", "isync_xput_mbps", isync_xput_mbps);
            printf("%28s=%8.2f\n", "isync_xput_per_core_mbps", isync_xput_per_core_mbps);
            printf("%28s=%8.2f\n", "isync_xput_per_call_mbps", isync_xput_per_call_mbps);
            printf("%28s=%8.2f\n", "isync_time_barr_per_call_us", isync_time_barr_per_call_us);
            printf("%28s=%8.2f\n", "isync_time_noop_per_call_us", isync_time_noop_per_call_us);
            printf("%28s=%8.2f\n", "isync_time_full_per_call_us", isync_time_full_per_call_us);
            printf("%28s=%8.2f\n", "overhead_isync_noop_pct", overhead_isync_noop);
            printf("%28s=%8.2f\n", "overhead_serv_pct", overhead_serv);
            printf("%28s=%8.2f\n", "overhead_log_pct", overhead_log);
            printf("%28s=%8.2f\n", "overhead_isync_full_pct", overhead_isync_full);
            printf("%28s=%8.2f\n", "overhead_direct_pct", overhead_direct);
            printf("%28s=%8.2f\n", "overhead_indirect_pct", overhead_indirect);
            printf("%28s=%8.2f\n", "overhead_full_pct", overhead_full);
            printf("\n");
        }
    }

    free(cfg.rand_arr);
    // service_loop();

    return 0;
}
