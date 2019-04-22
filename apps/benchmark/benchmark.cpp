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
#include <x86intrin.h>
#include <algorithm>
#include <iostream>
#include <random>
#include <type_traits>

#include <tasvir/tasvir.h>
#include <tasvir/array.hpp>

#include "simdxorshift128plus.h"

using namespace std;

enum WorkloadType : uint8_t {
    FIRST,
    WRITE_STREAM_RND,
    WRITE_STREAM_SEQ,
    WRITE_RND,
    WRITE_SEQ,
    READ_RND,
    READ_SEQ,
    LAST
};

static const char *workload_type_str[] = {"INVALID",   "WRITE_STREAM_RND", "WRITE_STREAM_SEQ", "WRITE_RND",
                                          "WRITE_SEQ", "READ_RND",         "READ_SEQ",         "INVALID"};
struct Stat {
    uint64_t runtime_us_per_mops;
    uint64_t write_mbps;
    uint64_t sync_mbps;
    uint64_t sync_changed_bps;
    uint64_t sync_processed_bps;
    uint64_t sync_pass_per_second;
    uint64_t sync_fail_per_second;
    uint64_t barr_us_per_second; /* amortized per call */
    uint64_t sync_us_per_second; /* amortized per call */
    double barr_us_per_call;
    double sync_us_per_call;
};

typedef __m512i Vec;

struct BenchmarkConfig {
    tasvir_area_desc *d;
    size_t area_len;

    int core;
    int wid;
    int nr_workers;
    int nr_writers;
    int nr_rounds;

    uint64_t sync_int_us;
    uint64_t sync_ext_us;

    long duration_ms;
    int service_us;

    WorkloadType wt;
    int stride;

    uint64_t nr_writes;
    int nr_writes_per_service;

    unsigned int cpu_family;
    unsigned int cpu_model;

    char compiler[32];

    Stat stats[2][2];
};

static __attribute__((unused)) void flush_cache() {
    int fd = open("/lib/modules/4.19.0-4-amd64/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (fd) {
        syscall(__NR_finit_module, fd, "", 0);
        syscall(__NR_delete_module, "wbinvd", 0);
        close(fd);
    }
}

static inline uint64_t tsc2usec(uint64_t tsc) { return 1E6 * tsc / rte_get_tsc_hz(); }

/*
static inline uint64_t rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

static uint32_t pcg32_random_r() {
    static struct {
        uint64_t state;
        uint64_t inc;
    } rng = {0x03535b53690c, 0xb8cca719e380};

    uint64_t oldstate = rng.state;
    // Advance internal state
    rng.state = oldstate * 6364136223846793005ULL + (rng.inc | 1);
    // Calculate output function (XSH RR), uses old state for max ILP
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

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

static inline uint64_t xorshift128plus() {
    static uint64_t s[2] = {0x03535b53690c, 0xb8cca719e380};
    uint64_t x = s[0];
    const uint64_t y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}
*/

static inline void cpuid(unsigned int &family, unsigned int &model) {
    /*
        stepping : 4
        model : 4
        family : 4
        processor_type : 2
        reserved : 2
        extended_model : 4
        extended_family : 8
    */
    int a[4];
    __cpuid(1, a[0], a[1], a[2], a[3]);
    family = ((a[0] >> 8) & 0xf) + ((a[0] >> 20) & 0xff);
    model = ((a[0] >> 4) & 0xf) + (((a[0] >> 16) & 0xf) << 4);
    if (family != 6) {
        fprintf(stderr, "Only CPU family 6 is supported.\n");
        abort();
    }
}

template <WorkloadType wt, typename T>
static inline __attribute__((__artificial__)) void op(void *__restrict dst, const T *__restrict src) {
    constexpr bool is_write = wt == WRITE_STREAM_RND || wt == WRITE_RND || wt == WRITE_STREAM_SEQ || wt == WRITE_SEQ;
    constexpr bool is_stream = wt == WRITE_STREAM_RND || wt == WRITE_STREAM_SEQ;

#ifdef __AVX512F__
    if (is_write && is_stream) {
        _mm512_stream_si512((__m512i *)dst, *(const __m512i *)src);
    } else if (is_write) {
        _mm512_store_si512(dst, *(const __m512i *)src);
    } else if (is_stream) {
    } else {
        *(volatile __m512i *)src;
    }
#elif __AVX2__
    if (is_write && is_stream) {
        _mm256_stream_si256((__m512i *)dst, *(const __m256i *)src);
    } else if (is_write) {
        _mm256_store_si256(dst, *(const __m256i *)src);
    } else if (is_stream) {
    } else {
        *(volatile __m256i *)src;
    }
#elif __AVX__
    if (is_write && is_stream) {
        _mm_stream_si128((__m512i *)dst, *(const __m128i *)src);
    } else if (is_write) {
        _mm_store_si128(dst, *(const __m128i *)src);
    } else if (is_stream) {
    } else {
        *(volatile __m128i *)src;
    }
#endif
}

static int init(BenchmarkConfig &cfg) {
#ifdef __clang__
    snprintf(cfg.compiler, sizeof(cfg.compiler), "clang_%d.%d.%d", __clang_major__, __clang_minor__,
             __clang_patchlevel__);
#elif __GNUC__
    snprintf(cfg.compiler, sizeof(cfg.compiler), "gcc_%d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
#error Expecting GCC or Clang
#endif
    cpuid(cfg.cpu_family, cfg.cpu_model);
    tasvir_area_desc *root_desc = tasvir_init(cfg.core);
    if (!root_desc) {
        fprintf(stderr, "tasvir_init failed\n");
        return -1;
    }
    cfg.area_len = 1UL << (64 - __builtin_clzl((cfg.area_len - 1) | 1));

    bool is_writer = (cfg.wid % (cfg.nr_workers / cfg.nr_writers)) == 0;
    tasvir_area_desc *d = nullptr;
    tasvir_area_desc param = {};
    param.pd = root_desc;
    param.len = is_writer ? cfg.area_len + 4096 + 8 * TASVIR_VEC_BYTES : sizeof(uint64_t);
    param.sync_int_us = cfg.sync_int_us;
    param.sync_ext_us = cfg.sync_ext_us;
    snprintf(param.name, sizeof(param.name), "benchmark-%d", cfg.wid);

    tasvir_area_desc *d_l[256];
    for (int i = 0; i < cfg.nr_workers; i++) {
        if (i == cfg.wid) {
            d = tasvir_new(param);
            if (!d) {
                fprintf(stderr, "tasvir_new %s failed\n", param.name);
                return -1;
            }
            d_l[i] = d;
        } else {
            tasvir_str name;
            snprintf(name, sizeof(name), "benchmark-%d", i);
            d_l[i] = tasvir_attach_wait(root_desc, name, false, 10 * 1000 * 1000);
            if (!d_l[i]) {
                fprintf(stderr, "tasvir_attach %s failed\n", name);
                return -1;
            }
        }
    }

    /* begin barrier */
    uint64_t done_flag = 0xdeadbeef;
    *(uint64_t *)tasvir_data(d) = done_flag;
    tasvir_log(tasvir_data(d), sizeof(uint64_t));
    while (tasvir_service_wait(1000 * 1000, false) != 0)
        ;

    for (int i = 0; i < cfg.nr_workers; i++)
        while (*(uint64_t *)tasvir_data(d_l[i]) != done_flag)
            tasvir_service_wait(1000 * 1000, false);

    tasvir_service_wait(1000 * 1000, false);
    /* end barrier */

    if (is_writer) {
        cfg.d = d;
        void *data = (void *)(((uintptr_t)tasvir_data(d) + TASVIR_VEC_BYTES - 1) & ~(TASVIR_VEC_BYTES - 1));
        memset(data, 0, cfg.area_len);
        memset(tasvir_data2shadow(data), 0, cfg.area_len);
    } else {
        printf("deactivating area\n");
        tasvir_area_activate(d, false);
        printf("entering service loop\n");
    }
    return 0;
}

static void usage(char *exec) {
    fprintf(stderr, "usage: %s [options]", exec);
    fprintf(stderr, "  -%c %-20s\n", 'c', "--core");
    fprintf(stderr, "  -%c %-20s\n", 'x', "--sync_int_us=INT");
    fprintf(stderr, "  -%c %-20s\n", 'X', "--sync_ext_us=INT");
    fprintf(stderr, "  -%c %-20s\n", 'i', "--wid=INT");
    fprintf(stderr, "  -%c %-20s\n", 'n', "--nr_workers=INT");
    fprintf(stderr, "  -%c %-20s\n", 'w', "--nr_writers=INT");
    fprintf(stderr, "  -%c %-20s\n", 'r', "--nr_rounds=INT");
    fprintf(stderr, "  -%c %-20s\n", 'd', "--duration_ms=INT");
    fprintf(stderr, "  -%c %-20s\n", 's', "--service_us=INT");
    fprintf(stderr, "  -%c %-20s\n", 'b', "--area_len=INT");
    fprintf(stderr, "  -%c %-20s\n", 'l', "--stride=INT");
    fprintf(stderr, "  -%c %-20s\n", 'h', "--help");
    exit(EXIT_FAILURE);
}

template <WorkloadType wt, bool do_service, bool do_log, int stride>
static __attribute__((noinline)) uint64_t experiment(BenchmarkConfig &__restrict cfg, bool calibrate = false) {
    constexpr bool is_random = wt == WRITE_STREAM_RND || wt == WRITE_RND || wt == READ_RND;

    tasvir_activate(do_service);
    tasvir_area_activate(cfg.d, do_service);

    avx512_xorshift128plus_key_t rndkey;
    avx512_xorshift128plus_init(324, 4444, &rndkey);

    struct {
        uint64_t addr_i[8];
        Vec addr_v;
        Vec src_v;
        Vec data_v;
        Vec mask_v;
        uint64_t data_i;
        uint64_t mask_i;
        uint64_t offset;
    } __attribute__((aligned(4096))) s;

    constexpr size_t alignment = (8 * stride) % 4096;
    s.src_v = avx512_xorshift128plus(&rndkey);
    s.data_i = ((uintptr_t)tasvir_data(cfg.d) + alignment - 1) & ~(alignment - 1);
    s.addr_i[0] = s.data_i;
    s.mask_i = (cfg.area_len - 1) & ~(TASVIR_VEC_BYTES - 1);
    s.offset = 0;
    if (is_random) {
        s.data_v = _mm512_set1_epi64(s.data_i);
        s.mask_v = _mm512_set1_epi64(s.mask_i);
        s.addr_v = s.data_v;
    }

    uint64_t nw = cfg.nr_writes;
    uint64_t nwps = do_service ? cfg.nr_writes_per_service : nw;
    uint64_t t_best = 0;
    int nr_rounds = calibrate ? 3 : cfg.nr_rounds;

    void *log_base = (void *)(TASVIR_ADDR_LOG + ((s.data_i - TASVIR_ADDR_DATA) >> TASVIR_SHIFT_BYTE));
    memset(log_base, 0, cfg.area_len / 512); // FIXME: replace 512 with proper macros
    for (int r = 0; r < nr_rounds; r++) {
        _mm_mfence();
        // flush_cache();
        tasvir_stats_reset();
        asm volatile("" ::: "memory");
        uint64_t t = __rdtsc();
        asm volatile("" ::: "memory");

        for (uint64_t i = 0; i < nw; i += nwps) {
            for (uint64_t ii = i; ii < i + nwps; ii += 8) {
                if (is_random) {
                    s.addr_v = avx512_xorshift128plus(&rndkey);
                    s.addr_v = _mm512_and_epi64(s.addr_v, s.mask_v);
                    s.addr_v = _mm512_add_epi64(s.addr_v, s.data_v);
                    _mm512_store_epi64(s.addr_i, s.addr_v);
                    for (int j = 0; j < 8; j++)
                        _mm_prefetch((void *)s.addr_i[j], _MM_HINT_ET0);
                    if (do_log)
                        for (int j = 0; j < 8; j++)
                            tasvir_log((void *)s.addr_i[j], stride);
                    for (int j = 0; j < 8; j++)
                        op<wt>((void *)s.addr_i[j], &s.src_v);
                } else {
                    s.addr_i[0] = s.data_i + ((ii * stride) & s.mask_i);
                    if (do_log)
                        tasvir_log((void *)s.addr_i[0], 8 * stride);
                    for (int j = 0; j < 8; j++)
                        op<wt>((void *)(s.addr_i[0] + j * stride), &s.src_v);
                }
            }

            if (do_service) {
                tasvir_service();
            }
        }

        asm volatile("" ::: "memory");
        t = tsc2usec(__rdtsc() - t);
        asm volatile("" ::: "memory");
        if (r == 0 || t < t_best)
            t_best = t;

        if (calibrate)
            continue;

        tasvir_stats ts = tasvir_stats_get();
        double mult = 1E6 / t;
        Stat stat;
        stat.sync_pass_per_second = mult * ts.success;
        stat.sync_fail_per_second = mult * ts.failure;
        stat.runtime_us_per_mops = 1E6 * t / cfg.nr_writes;
        stat.barr_us_per_call = (double)ts.sync_barrier_us / ts.success; /* TODO: check denom */
        stat.sync_us_per_call = (double)ts.sync_us / ts.success;         /* TODO: check denom */
        stat.barr_us_per_second = mult * ts.sync_barrier_us;
        stat.sync_us_per_second = mult * ts.sync_us;
        stat.sync_changed_bps = mult * ts.sync_changed_bytes;
        stat.sync_processed_bps = mult * ts.sync_processed_bytes;
        stat.write_mbps = cfg.stride * cfg.nr_writes / t;
        stat.sync_mbps = ts.sync_us ? ts.sync_changed_bytes / ts.sync_us : 0;

        if (t == t_best)
            cfg.stats[do_log][do_service] = stat;

        printf(
            "round=%2d service=%d log=%d: write_mbps=%6lu barr_us_per_call=%4.1f sync_us_per_call=%7.1f "
            "sync_changed_kbps=%8ld sync_processed_kbps=%11ld sync_pass_ps=%6ld sync_fail_ps=%6ld t_ms=%5lu "
            "writes_k=%lu\n",
            r + 1, do_service, do_log, stat.write_mbps, stat.barr_us_per_call, stat.sync_us_per_call,
            stat.sync_changed_bps / 1000, stat.sync_processed_bps / 1000, stat.sync_pass_per_second,
            stat.sync_fail_per_second, t / 1000, cfg.nr_writes / 1000);
    }

    return t_best;
}

template <WorkloadType wt, int stride>
static typename enable_if<wt == WorkloadType::FIRST, void>::type experiment_runner(BenchmarkConfig &) {}

template <WorkloadType wt, int stride>
static typename enable_if<wt != WorkloadType::FIRST, void>::type experiment_runner(BenchmarkConfig &cfg) {
    /* warmup and calibration */
    tasvir_activate(false);
    tasvir_area_activate(cfg.d, false);
    /* short run to calibrate cfg.nr_writes */
    cfg.nr_writes = 10 * 1000 * 1000;
    uint64_t t = experiment<wt, false, false, stride>(cfg, true);
    cfg.nr_writes_per_service = cfg.nr_writes * cfg.service_us / (double)t;
    cfg.nr_writes_per_service -= cfg.nr_writes_per_service % 8;
    cfg.nr_writes = 1000 * cfg.nr_writes * cfg.duration_ms / (double)t;
    cfg.nr_writes -= cfg.nr_writes % cfg.nr_writes_per_service;
    cfg.stride = stride;
    cfg.wt = wt;
    printf(
        "workload=%s area_len_kb=%lu stride_b=%d cpu=%d-%d compiler=%s wid=%d core=%d "
        "nr_workers=%d nr_writers=%d service_us=%d sync_int_us=%lu sync_ext_us=%lu\n",
        workload_type_str[cfg.wt], cfg.area_len / 1000, cfg.stride, cfg.cpu_family, cfg.cpu_model, cfg.compiler,
        cfg.wid, cfg.core, cfg.nr_workers, cfg.nr_writers, cfg.service_us, cfg.sync_int_us, cfg.sync_ext_us);

    // experiment<wt, false, false, stride>(cfg);
    // experiment<wt, false, true, stride>(cfg);
    // experiment<wt, true, false, stride>(cfg);
    experiment<wt, true, true, stride>(cfg);

    auto &s = cfg.stats;
    double overhead_isync_noop_pct = 100. * s[0][1].sync_us_per_second / (1E6 - s[0][1].sync_us_per_second);
    double overhead_isync_full_pct = 100. * s[1][1].sync_us_per_second / (1E6 - s[1][1].sync_us_per_second);
    double overhead_log_pct =
        100. * ((double)s[1][0].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops;
    double overhead_noop_pct =
        100. * ((double)s[0][1].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops;
    double overhead_full_pct =
        100. * ((double)s[1][1].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops;

    double overhead_srv_pct = overhead_noop_pct - overhead_isync_noop_pct;
    double overhead_direct_pct = overhead_log_pct + overhead_isync_full_pct + overhead_srv_pct;
    double overhead_indirect_pct = overhead_full_pct - overhead_direct_pct;

    for (int do_service = 0; do_service <= 1; do_service++)
        for (int do_log = 0; do_log <= 1; do_log++)
            printf("        write_xput_l%ds%d_mbps=%8lu\n", do_log, do_service, s[do_log][do_service].write_mbps);

    printf("%28s=%8.2f\n", "isync_write_pct", 1E-4 * s[1][1].sync_changed_bps / s[1][1].write_mbps);
    printf("%28s=%8lu\n", "isync_xput_mbps", s[1][1].sync_mbps);
    printf("%28s=%8lu\n", "isync_xput_mbps_per_core", s[1][1].sync_mbps / (cfg.nr_workers + 1));
    printf("%28s=%8lu\n", "isync_xput_mbps_per_call", s[1][1].sync_mbps / s[1][1].sync_pass_per_second);

    printf("%28s=%8.2f\n", "isync_barr_noop_us_per_call", s[0][1].barr_us_per_call);
    printf("%28s=%8.2f\n", "isync_barr_full_us_per_call", s[1][1].barr_us_per_call);
    printf("%28s=%8.2f\n", "isync_noop_us_per_call", s[0][1].sync_us_per_call);
    printf("%28s=%8.2f\n", "isync_full_us_per_call", s[1][1].sync_us_per_call);

    printf("%28s=%8.2f\n", "overhead_noop_pct", overhead_noop_pct);
    printf("%28s=%8.2f\n", "overhead_isync_noop_pct", overhead_isync_noop_pct);
    printf("%28s=%8.2f\n", "overhead_srv_pct", overhead_srv_pct);
    printf("%28s=%8.2f\n", "overhead_log_pct", overhead_log_pct);
    printf("%28s=%8.2f\n", "overhead_isync_full_pct", overhead_isync_full_pct);
    printf("%28s=%8.2f\n", "overhead_direct_pct", overhead_direct_pct);
    printf("%28s=%8.2f\n", "overhead_indirect_pct", overhead_indirect_pct);
    printf("%28s=%8.2f\n", "overhead_full_pct", overhead_full_pct);
    printf("\n");
}

int main(int argc, char **argv) {
    alignas(4096) BenchmarkConfig cfg = {};
    cfg.sync_int_us = 1000;
    cfg.sync_ext_us = 1000 * 1000 * 1000;
    cfg.nr_workers = 1;
    cfg.nr_writers = 1;
    cfg.nr_rounds = 3;
    cfg.duration_ms = 1000;
    cfg.service_us = 10;
    cfg.area_len = 1000 * 1000;
    cfg.stride = 64;

    while (1) {
        static struct option long_options[] = {{"core", required_argument, 0, 'c'},
                                               {"sync_int_us", required_argument, 0, 'x'},
                                               {"sync_ext_us", required_argument, 0, 'X'},
                                               {"wid", required_argument, 0, 'i'},
                                               {"nr_workers", required_argument, 0, 'n'},
                                               {"nr_writers", required_argument, 0, 'w'},
                                               {"nr_rounds", required_argument, 0, 'r'},
                                               {"duration_ms", required_argument, 0, 'd'},
                                               {"service_us", required_argument, 0, 's'},
                                               {"area_len", required_argument, 0, 'b'},
                                               {"stride", required_argument, 0, 'l'},
                                               {"help", no_argument, 0, 'h'},
                                               {0, 0, 0, 0}};
        int c = getopt_long(argc, argv, "c:x:X:i:n:r:w:d:s:b:l:h", long_options, nullptr);
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
        case 'r':
            cfg.nr_rounds = atoi(optarg);
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
            cfg.area_len = atol(optarg);
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

    printf("cmdline: ");
    for (int i = 0; i < argc; i++)
        printf("%s ", argv[i]);

    if (init(cfg) != 0)
        return -1;

    constexpr int stride = TASVIR_VEC_BYTES;
    cfg.stride = stride;

    bool is_writer = (cfg.wid % (cfg.nr_workers / cfg.nr_writers)) == 0;
    if (is_writer) {
        // experiment_runner<WorkloadType::WRITE_SEQ, stride>(cfg);
        experiment_runner<WorkloadType::WRITE_RND, stride>(cfg);
    } else {
        while (true) {
            // experiment_runner<WorkloadType::READ_RND, stride>(cfg);
            tasvir_service();
            rte_delay_us_block(cfg.service_us);
        }
    }

    return 0;
}
