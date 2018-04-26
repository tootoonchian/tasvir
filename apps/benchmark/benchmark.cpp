#include <fcntl.h>
#include <rte_cycles.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <iostream>
#include <random>

#include "tasvir.h"

int do_log, do_service;
using namespace std;

#define RNDCNT (1024 * 1024)
static uint64_t rand_arr[RNDCNT];
uint64_t s[2];

uint64_t xorshift128plus(void) {
    uint64_t x = s[0];
    uint64_t const y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}

double normalize_overhead(double i) { return i > 0 ? i : 0; }

void init_rnd(void) {
    size_t i;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> dist_offset(0, UINT64_MAX);
    for (i = 0; i < 2; i++)
        s[i] = dist_offset(gen);
    for (i = 0; i < RNDCNT; i++)
        rand_arr[i] = dist_offset(gen);
}

void *random_write(uint8_t *addr, size_t len, int stride) {
    size_t offset = xorshift128plus() & (len - 1) & (~63UL);
    addr += offset;
    memcpy(addr, &rand_arr[offset & (RNDCNT - 1)], stride);
    return addr;
}

void flush_cache() {
    int fd = open("/lib/modules/4.15.0-2-amd64/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (!fd)
        return;
    syscall(__NR_finit_module, fd, "", 0);
    syscall(__NR_delete_module, "wbinvd", 0);
    close(fd);
}

uint64_t gettime_us() { return 1E6 * rte_rdtsc() / rte_get_tsc_hz(); }

uint64_t experiment(tasvir_area_desc *d, size_t len, int count, int iter, int stride) {
    int i;
    void *addr;
    uint64_t time_us = gettime_us();

    if (do_log && do_service) {
        while ((count -= iter) > 0) {
            i = iter;
            while (i--) {
                addr = random_write((uint8_t *)tasvir_data(d), len, stride);
                tasvir_log_write(addr, stride);
            }
            tasvir_service();
        }
    } else if (do_log) {
        while ((count -= iter) > 0) {
            i = iter;
            while (i--) {
                addr = random_write((uint8_t *)tasvir_data(d), len, stride);
                tasvir_log_write(addr, stride);
            }
        }
    } else if (do_service) {
        while ((count -= iter) > 0) {
            i = iter;
            while (i--) {
                addr = random_write((uint8_t *)tasvir_data(d), len, stride);
            }
            tasvir_service();
        }
    } else {
        while ((count -= iter) > 0) {
            i = iter;
            while (i--) {
                addr = random_write((uint8_t *)tasvir_data(d), len, stride);
            }
        }
    }

    return (gettime_us() - time_us) / 1000;
}

int next_pow2(int x) { return 1 << (32 - __builtin_clz((x - 1) | 1)); }

int main(int argc, char **argv) {
    if (argc != 11) {
        fprintf(stderr,
                "usage: %s tid core nthreads tid_modulo nr_updates nr_updates_per_service area_bytes stride sync_int "
                "sync_ext\n",
                argv[0]);
        return -1;
    }
    int tid = atoi(argv[1]);
    int core = atoi(argv[2]);
    int nthreads = atoi(argv[3]);
    int writer_modulo = atoi(argv[4]);
    int count = next_pow2(atoi(argv[5]));
    int iter = next_pow2(atoi(argv[6]));
    size_t area_len = next_pow2(atol(argv[7]));
    int stride = atoi(argv[8]);
    int sync_int = atoi(argv[9]);
    int sync_ext = atoi(argv[10]);

    uint64_t time_ms[2][2];
    tasvir_sync_stats stats[2][2];
    double overhead_service, overhead_sync, overhead_log, overhead_direct, overhead_indirect, overhead_full;

    init_rnd();

    tasvir_area_desc *root_desc = tasvir_init(TASVIR_THREAD_TYPE_APP, core, NULL);
    if (!root_desc) {
        fprintf(stderr, "%s: tasvir_init failed\n", argv[0]);
        return -1;
    }

    tasvir_area_desc *d = NULL;
    for (int i = 0; i < nthreads; i += writer_modulo) {
        if (tid == i) {
            tasvir_area_desc param = {};
            param.pd = root_desc;
            param.owner = NULL;
            param.type = TASVIR_AREA_TYPE_APP;
            param.len = area_len + stride;
            param.sync_int_us = sync_int;
            param.sync_ext_us = sync_ext;
            snprintf(param.name, sizeof(param.name), "benchmark-%d", tid);
            d = tasvir_new(param);
            if (!d) {
                fprintf(stderr, "%s: tasvir_new %s failed\n", argv[0], param.name);
                return -1;
            }
        } else {
            tasvir_str name;
            snprintf(name, sizeof(name), "benchmark-%d", i);
            if (tasvir_attach_wait(root_desc, name, NULL, false, 5 * 1000 * 1000) == NULL) {
                fprintf(stderr, "%s: tasvir_attach %s failed\n", argv[0], name);
                return -1;
            }
        }
    }

    if (d) {
        for (do_service = 1; do_service >= 0; do_service--) {
            for (do_log = 1; do_log >= 0; do_log--) {
                fprintf(stderr, "   log%c service%c\n", do_log ? '+' : '-', do_service ? '+' : '-');
                uint64_t time_us = gettime_us();
                while (gettime_us() - time_us < 1000 * 1000)
                    tasvir_service();
                tasvir_sync_stats_reset();
                memset(tasvir_data2log(d->h), 0, area_len >> TASVIR_SHIFT_BYTE);
                flush_cache();

                time_ms[do_log][do_service] = experiment(d, area_len, count, iter, stride);
                stats[do_log][do_service] = tasvir_sync_stats_get();
            }
        }

        for (do_log = 0; do_log < 2; do_log++) {
            for (do_service = 0; do_service < 2; do_service++) {
                fprintf(stderr, "   log%c service%c: %5ld ms (sync: count=%5ld, time_ms=%5ld, size=%9ldkB)\n",
                        do_log ? '+' : '-', do_service ? '+' : '-', time_ms[do_log][do_service],
                        stats[do_log][do_service].count, stats[do_log][do_service].cumtime_us / 1000,
                        stats[do_log][do_service].cumbytes / 1000);
            }
        }
        fprintf(stderr, "\n");

        overhead_service = normalize_overhead(100. * ((long)time_ms[0][1] - (long)time_ms[0][0]) / time_ms[0][0]);
        overhead_sync = (double)stats[1][1].cumtime_us / (10 * time_ms[0][0]);
        overhead_log = normalize_overhead(100. * ((long)time_ms[1][0] - (long)time_ms[0][0]) / time_ms[0][0]);
        overhead_full = normalize_overhead(100. * ((long)time_ms[1][1] - (long)time_ms[0][0]) / time_ms[0][0]);
        overhead_direct = overhead_log + overhead_sync;
        overhead_indirect = normalize_overhead(overhead_full - overhead_direct);
        fprintf(stderr, " service overhead: %5.2f%%\n", overhead_service);
        fprintf(stderr, "    sync overhead: %5.2f%%\n", overhead_sync);
        fprintf(stderr, "     log overhead: %5.2f%%\n", overhead_log);
        fprintf(stderr, "  direct overhead: %5.2f%%\n", overhead_direct);
        fprintf(stderr, "indirect overhead: %5.2f%%\n", overhead_indirect);
        fprintf(stderr, "    full overhead: %5.2f%%\n", overhead_full);
    }

    while (1) {
        tasvir_service();
        rte_delay_us(1);
    }

    return 0;
}
