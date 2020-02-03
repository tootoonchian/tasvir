#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <random>
#include <type_traits>

#include <cpuid.h>
#include <fcntl.h>
#include <getopt.h>
#include <immintrin.h>
#include <rte_cycles.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <x86intrin.h>

#include <tasvir/tasvir.h>

#include "simdxorshift128plus.h"

using namespace std;

#define MS2US (1000)
#define S2US (1000 * MS2US)

#ifdef __AVX512F__
typedef __m512i Vec;
#define vec_store _mm512_store_si512
#elif __AVX2__
typedef __m256i Vec;
#define vec_store _mm256_store_si256
#elif __AVX__
typedef __m128i Vec;
#define vec_store _mm_store_si128
#endif

enum OpType : uint8_t {
    OP_WRITE,
    OP_READ,
};

enum WorkloadType : uint8_t { W100, R100, W50R50, W12R88, W88R12 };
constexpr int nr_writes_per_iter[] = {8, 0, 4, 1, 7};

static const char *workload_type_str[] = {"W100", "R100", "W50R50", "W12R88", "W88R12"};

enum DistType : uint8_t {
    DIST_SEQ,
    DIST_RND,
};

static const char *dist_type_str[] = {"SEQ", "RND"};

struct Stat {
    uint64_t runtime_us_per_mops;
    uint64_t op_mbps;
    uint64_t isync_mbps;
    uint64_t isync_changed_bps;
    uint64_t isync_processed_bps;
    uint64_t isync_pass_per_second;
    uint64_t isync_fail_per_second;
    uint64_t isync_barr_us_per_second; /* amortized per call */
    uint64_t isync_us_per_second;      /* amortized per call */
    double isync_barr_us_per_call;
    double isync_us_per_call;
};

struct BenchmarkConfig {
    tasvir_area_desc *d;
    size_t area_len;

    int wid;
    int nr_workers;
    int nr_writers;
    int nr_rounds;

    uint64_t sync_int_us;
    uint64_t sync_ext_us;

    long duration_ms;
    int service_us;

    int stride;

    uint64_t nr_ops;
    int nr_ops_per_service;

    unsigned int cpu_family;
    unsigned int cpu_model;

    char compiler[32];

    Stat stats[2][2];

    bool dummy;
};

#ifdef TASVIR_BENCHMARK_WBINVD
static __attribute__((unused)) void flush_cache() {
    int fd = open("/lib/modules/4.19.0-5-amd64/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (fd) {
        syscall(__NR_finit_module, fd, "", 0);
        syscall(__NR_delete_module, "wbinvd", 0);
        close(fd);
    }
}
#endif

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

template <OpType t, bool do_log, int stride, typename T>
static inline __attribute__((__artificial__)) void op(void *__restrict dst, const T *__restrict src) {
    const Vec *__restrict src_v = src;
    Vec *__restrict dst_v = (Vec *)dst;
    constexpr int n = stride / sizeof(Vec);
    for (int i = 0; i < n; i++) {
        if (t == OP_WRITE) {
            if (do_log)
                tasvir_log(&dst_v[i], sizeof(Vec));
            vec_store(&dst_v[i], src_v[i]);
        } else {
            *(volatile Vec *)&dst_v[i];
        }
    }
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
    tasvir_area_desc *root_desc = tasvir_init();
    if (!root_desc) {
        fprintf(stderr, "tasvir_init failed\n");
        return -1;
    }
    // cfg.area_len = 1UL << (64 - __builtin_clzl((cfg.area_len - 1) | 1));
    cfg.area_len = TASVIR_ALIGNX(cfg.area_len, 8 * sizeof(Vec));

    bool is_writer = (cfg.wid % (cfg.nr_workers / cfg.nr_writers)) == 0;
    tasvir_area_desc *d = nullptr;
    tasvir_area_desc param = {};
    param.pd = root_desc;
    param.len = is_writer ? cfg.area_len + 4096 : sizeof(uint64_t);
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
            d_l[i] = tasvir_attach_wait(10 * S2US, name);
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
    while (tasvir_service_wait(S2US, false) != 0)
        ;

    for (int i = 0; i < cfg.nr_workers; i++)
        while (*(uint64_t *)tasvir_data(d_l[i]) != done_flag)
            tasvir_service_wait(S2US, false);

    tasvir_service_wait(S2US, false);
    /* end barrier */

    if (is_writer) {
        cfg.d = d;
        void *data = (void *)(((uintptr_t)tasvir_data(d) + sizeof(Vec) - 1) & ~(sizeof(Vec) - 1));
        memset(data, 0, cfg.area_len);
        // TODO: test if necessary
        // memset(tasvir_data2shadow(data), 0, cfg.area_len);
    } else {
        cfg.d = d_l[0];
        printf("deactivating area\n");
        tasvir_area_activate(d, false);
        printf("entering service loop\n");
    }
    return 0;
}

static void usage(char *exec) {
    fprintf(stderr, "usage: %s [options]", exec);
    // fprintf(stderr, "  -%c %-20s\n", 'c', "--core");
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

void __attribute__((noinline)) log(void *addr, size_t len) { tasvir_log(addr, len); }

template <WorkloadType wt, DistType dt, bool do_service, bool do_log, bool do_prefetch, int stride>
static __attribute__((noinline)) uint64_t experiment(BenchmarkConfig &__restrict cfg, bool calibrate = false) {
    constexpr bool is_random = dt == DistType::DIST_RND;
    tasvir_activate(do_service);
    tasvir_area_activate(cfg.d, do_service);

    avx512_xorshift128plus_key_t rndkey;
    avx512_xorshift128plus_init(324, 4444, &rndkey);

    Vec *__restrict data_i = (Vec *)TASVIR_ALIGNX(tasvir_data(cfg.d), 4096);
    uint64_t offset_i[8];
    Vec src_v = avx512_xorshift128plus(&rndkey);
    if ((uintptr_t)data_i + cfg.area_len > (uintptr_t)tasvir_data(cfg.d) + cfg.d->len_logged) {
        fprintf(stderr, "insufficient space allocated. aborting...");
        return 0;
    }

    uint64_t nw = cfg.nr_ops;
    uint64_t nwps = do_service ? cfg.nr_ops_per_service : nw;
    uint64_t t_best = 0;
    int nr_rounds = calibrate ? 3 : cfg.nr_rounds;
    size_t offset_max = cfg.area_len / sizeof(Vec);

    for (int r = 0; r < nr_rounds; r++) {
        // clear out anything remaining from past
        if (do_service)
            while (tasvir_service_wait(S2US, false) != 0)
                ;
        _mm_mfence();
#ifdef TASVIR_BENCHMARK_WBINVD
        flush_cache();
#endif
        if (cfg.wid == 0)
            tasvir_stats_reset();
        asm volatile("" ::: "memory");
        uint64_t t = __rdtsc();
        asm volatile("" ::: "memory");

        for (uint64_t i = 0; i < nw; i += nwps) {
            for (uint64_t ii = i; ii < i + nwps; ii += 8) {
                if (is_random) {
                    _mm512_store_epi64(offset_i, avx512_xorshift128plus(&rndkey));
                    for (int j = 0; j < 8; j++)
                        offset_i[j] = (uint64_t)(offset_i[j] % offset_max);
                    for (int j = 0; do_prefetch && j < 8; j++)
                        _mm_prefetch((void *)(data_i + offset_i[j]), _MM_HINT_T0);
                    for (int j = 0; do_log && j < nr_writes_per_iter[wt]; j++)
                        tasvir_log((void *)(data_i + offset_i[j]), stride);
                } else {
                    size_t base = (ii * stride) % offset_max;
                    for (int j = 0; j < 8; j++)
                        offset_i[j] = (uint64_t)(base + j * stride);
                    for (int j = 0; do_prefetch && j < 8; j++)
                        _mm_prefetch((void *)(data_i + offset_i[j]), _MM_HINT_T0);
                    if (do_log)
                        tasvir_log((void *)(data_i + offset_i[0]), nr_writes_per_iter[wt] * stride);
                }

                for (int j = 0; j < 8; j++)
                    if (j < nr_writes_per_iter[wt])
                        op<OpType::OP_WRITE, false, stride>((void *)(data_i + offset_i[j]), &src_v);
                    else
                        op<OpType::OP_READ, false, stride>((void *)(data_i + offset_i[j]), &src_v);
            }

            if (do_service)
                tasvir_service();
        }

        asm volatile("" ::: "memory");
        t = 1E6 * (__rdtsc() - t) / rte_get_tsc_hz();
        asm volatile("" ::: "memory");
        if (r == 0 || t < t_best)
            t_best = t;

        if (calibrate)
            continue;

        tasvir_stats ts = tasvir_stats_get();
        double mult = 1E6 / t;
        Stat stat;
        stat.isync_pass_per_second = mult * ts.isync_success;
        stat.isync_fail_per_second = mult * ts.isync_failure;
        stat.runtime_us_per_mops = 1E6 * t / cfg.nr_ops;
        stat.isync_barr_us_per_call = (double)ts.isync_barrier_us / ts.isync_success; /* TODO: check denom */
        stat.isync_us_per_call = (double)ts.isync_us / ts.isync_success;              /* TODO: check denom */
        stat.isync_barr_us_per_second = mult * ts.isync_barrier_us;
        stat.isync_us_per_second = mult * ts.isync_us;
        stat.isync_changed_bps = mult * ts.isync_changed_bytes;
        stat.isync_processed_bps = mult * ts.isync_processed_bytes;
        stat.op_mbps = cfg.stride * cfg.nr_ops / t;
        stat.isync_mbps = ts.isync_us ? ts.isync_changed_bytes / ts.isync_us : 0;

        if (t == t_best)
            cfg.stats[do_log][do_service] = stat;

        printf(
            "round=%2d service=%d log=%d: op_mbps=%6lu barr_us_per_call=%4.1f isync_us_per_call=%7.1f "
            "isync_changed_kbps=%8ld isync_processed_kbps=%11ld isync_pass_ps=%6ld isync_fail_ps=%6ld t_ms=%5lu "
            "writes_k=%lu\n",
            r + 1, do_service, do_log, stat.op_mbps, stat.isync_barr_us_per_call, stat.isync_us_per_call,
            stat.isync_changed_bps / 1000, stat.isync_processed_bps / 1000, stat.isync_pass_per_second,
            stat.isync_fail_per_second, t / 1000, cfg.nr_ops / 1000);
    }

    return t_best;
}

template <WorkloadType wt, DistType dt, int stride>
static void experiment_runner(BenchmarkConfig &cfg) {
    /* warmup and calibration */
    tasvir_activate(false);
    tasvir_area_activate(cfg.d, false);
    /* short run to calibrate cfg.nr_ops */
    cfg.nr_ops = 10 * 1000 * 1000;
    bool do_prefetch = cfg.area_len > 512 * 1024;
    uint64_t t;
    t = experiment<wt, dt, false, false, false, stride>(cfg, true);
    cfg.nr_ops_per_service = cfg.nr_ops * cfg.service_us / (double)t;
    cfg.nr_ops_per_service -= cfg.nr_ops_per_service % 80;
    cfg.nr_ops = 1000 * cfg.nr_ops * cfg.duration_ms / (double)t;
    cfg.nr_ops -= cfg.nr_ops % cfg.nr_ops_per_service;
    cfg.stride = stride;
    printf(
        "workload=%s_%s area_len_kb=%lu stride_b=%d cpu=%d-%d compiler=%s wid=%d core=%s "
        "nr_workers=%d nr_writers=%d service_us=%d sync_int_us=%lu sync_ext_us=%lu\n",
        dist_type_str[dt], workload_type_str[wt], cfg.area_len / 1000, cfg.stride, cfg.cpu_family, cfg.cpu_model,
        cfg.compiler, cfg.wid, getenv("TASVIR_CORE"), cfg.nr_workers, cfg.nr_writers, cfg.service_us, cfg.sync_int_us,
        cfg.sync_ext_us);

    if (do_prefetch) {
        experiment<wt, dt, false, false, true, stride>(cfg);
        experiment<wt, dt, false, true, true, stride>(cfg);
        experiment<wt, dt, true, false, true, stride>(cfg);
        experiment<wt, dt, true, true, true, stride>(cfg);
    } else {
        experiment<wt, dt, false, false, false, stride>(cfg);
        experiment<wt, dt, false, true, false, stride>(cfg);
        experiment<wt, dt, true, false, false, stride>(cfg);
        experiment<wt, dt, true, true, false, stride>(cfg);
    }

    auto &s = cfg.stats;
    double overhead_isync_noop_pct = 100. * s[0][1].isync_us_per_second / (1E6 - s[0][1].isync_us_per_second);
    double overhead_isync_full_pct = 100. * s[1][1].isync_us_per_second / (1E6 - s[1][1].isync_us_per_second);
    double overhead_log_pct = max(
        0., 100. * ((double)s[1][0].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops);
    double overhead_noop_pct =
        100. * ((double)s[0][1].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops;
    double overhead_full_pct =
        100. * ((double)s[1][1].runtime_us_per_mops - s[0][0].runtime_us_per_mops) / s[0][0].runtime_us_per_mops;

    double overhead_srv_pct = max(overhead_noop_pct - overhead_isync_noop_pct, 0.);
    double overhead_direct_pct = overhead_isync_full_pct + overhead_log_pct + overhead_srv_pct;
    double overhead_indirect_pct = overhead_full_pct - overhead_direct_pct;

    for (int do_service = 0; do_service <= 1; do_service++)
        for (int do_log = 0; do_log <= 1; do_log++)
            printf("        write_xput_l%ds%d_mbps=%8lu\n", do_log, do_service, s[do_log][do_service].op_mbps);

    printf("%28s=%8.2f\n", "isync_write_pct", 1E-4 * s[1][1].isync_changed_bps / s[1][1].op_mbps);
    printf("%28s=%8lu\n", "isync_xput_mbps", s[1][1].isync_mbps);
    printf("%28s=%8lu\n", "isync_xput_mbps_per_core", s[1][1].isync_mbps / (cfg.nr_workers + 1));
    printf("%28s=%8lu\n", "isync_xput_mbps_per_call", s[1][1].isync_mbps / s[1][1].isync_pass_per_second);

    printf("%28s=%8.2f\n", "isync_barr_noop_us_per_call", s[0][1].isync_barr_us_per_call);
    printf("%28s=%8.2f\n", "isync_barr_full_us_per_call", s[1][1].isync_barr_us_per_call);
    printf("%28s=%8.2f\n", "isync_noop_us_per_call", s[0][1].isync_us_per_call);
    printf("%28s=%8.2f\n", "isync_full_us_per_call", s[1][1].isync_us_per_call);

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
    cfg.sync_int_us = MS2US;
    cfg.sync_ext_us = 1000 * S2US;
    cfg.nr_workers = 1;
    cfg.nr_writers = 1;
    cfg.nr_rounds = 3;
    cfg.duration_ms = 1000;
    cfg.service_us = 10;
    cfg.area_len = 1000 * 1000;
    cfg.stride = 64;

    while (1) {
        static struct option long_options[] = {//{"core", required_argument, 0, 'c'},
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
        int c = getopt_long(argc, argv, "x:X:i:n:r:w:d:s:b:l:h", long_options, nullptr);
        if (c == -1)
            break;

        switch (c) {
        case 'x':
            cfg.sync_int_us = atol(optarg);
            break;
        case 'X':
            cfg.sync_ext_us = atol(optarg);
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
            cfg.stride = (atoi(optarg) + sizeof(Vec) - 1) & ~(sizeof(Vec) - 1);
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

    constexpr int stride = sizeof(Vec);
    cfg.stride = stride;

    bool is_writer = (cfg.wid % (cfg.nr_workers / cfg.nr_writers)) == 0;
    cfg.dummy = !is_writer;
    if (is_writer) {
        experiment_runner<WorkloadType::W100, DistType::DIST_SEQ, stride>(cfg);
        experiment_runner<WorkloadType::W100, DistType::DIST_RND, stride>(cfg);
        experiment_runner<WorkloadType::W12R88, DistType::DIST_SEQ, stride>(cfg);
        experiment_runner<WorkloadType::W12R88, DistType::DIST_RND, stride>(cfg);
    } else {
        cfg.nr_ops = 10 * 1000 * 1000;
        uint64_t t = experiment<WorkloadType::R100, DistType::DIST_RND, false, false, false, stride>(cfg, true);
        cfg.nr_ops_per_service = cfg.nr_ops * cfg.service_us / (double)t;
        cfg.nr_ops_per_service -= cfg.nr_ops_per_service % 80;
        cfg.nr_ops = 1000 * cfg.nr_ops * cfg.duration_ms / (double)t;
        cfg.nr_ops -= cfg.nr_ops % cfg.nr_ops_per_service;

        while (true) {
            experiment<WorkloadType::R100, DistType::DIST_RND, true, false, false, stride>(cfg);
            /*
               tasvir_service();
               rte_delay_us_block(cfg.service_us);
            */
        }
    }

    return 0;
}
