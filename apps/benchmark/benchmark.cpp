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

void init(void) {
    size_t i;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> dist_offset(0, UINT64_MAX);

    for (i = 0; i < 2; i++)
        s[i] = dist_offset(gen);
    for (i = 0; i < RNDCNT; i++)
        rand_arr[i] = dist_offset(gen);
}

void random_write(uint8_t *addr, size_t len, int stride) {
    size_t offset = xorshift128plus() % (len - stride);
    addr += offset;
    memcpy(addr, &rand_arr[offset % RNDCNT], stride);
    if (do_log)
        tasvir_log_write(addr, stride);
}

void flush_cache() {
    int fd = open("/lib/modules/4.10.0-rc1+/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (!fd) {
        return;
    }

    syscall(__NR_finit_module, fd, "", 0);
    syscall(__NR_delete_module, "wbinvd", 0);
}

uint64_t gettime_us() { return 1E6 * rte_rdtsc() / rte_get_tsc_hz(); }

uint64_t experiment(tasvir_area_desc *d, size_t len, int count, int iter, int stride) {
    uint64_t time_us = gettime_us();
    while (gettime_us() - time_us < 1000 * 1000)
        tasvir_service();

    flush_cache();
    tasvir_sync_stats_reset();
    memset(tasvir_data2log(d->h), 0, len >> TASVIR_SHIFT_BYTE);
    time_us = gettime_us();
    int i;
    while (count > 0) {
        count -= iter;
        i = iter;
        while (i--)
            random_write((uint8_t *)tasvir_data(d), len - stride, stride);
        if (do_service)
            tasvir_service();
    }

    return (gettime_us() - time_us) / 1000;
}

int main(int argc, char **argv) {
    if (argc != 8) {
        fprintf(stderr, "usage: %s core nr_updates nr_updates_per_service area_bytes stride sync_int sync_ext\n",
                argv[0]);
        return -1;
    }
    int core = atoi(argv[1]);
    int count = atoi(argv[2]);
    int iter = atoi(argv[3]);
    size_t area_len = atol(argv[4]);
    int stride = atoi(argv[5]);
    int sync_int = atoi(argv[6]);
    int sync_ext = atoi(argv[7]);

    init();

    tasvir_area_desc *root_desc = tasvir_init(TASVIR_THREAD_TYPE_APP, core, NULL);
    if (!root_desc) {
        fprintf(stderr, "%s: tasvir_init failed\n", argv[0]);
        return -1;
    }

    tasvir_area_desc param = {};
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = area_len;
    param.sync_int_us = sync_int;  // 10000;
    param.sync_ext_us = sync_ext;  // 100000;
    snprintf(param.name, sizeof(param.name), "benchmark-%04x", static_cast<uint16_t>(xorshift128plus()));
    tasvir_area_desc *d = tasvir_new(param);
    if (!d) {
        fprintf(stderr, "%s: tasvir_new failed\n", argv[0]);
        return -1;
    }

    // do_service = do_log = true;
    // fprintf(stderr, "took %ld msecs\n", experiment(d, area_len, count, iter, stride));
    // return 0;

    uint64_t time_ms[2][2];
    tasvir_sync_stats stats[2][2];
    for (do_service = 1; do_service >= 0; do_service--) {
        for (do_log = 1; do_log >= 0; do_log--) {
            fprintf(stderr, "   log%c service%c\n", do_log ? '+' : '-', do_service ? '+' : '-');
            time_ms[do_log][do_service] = experiment(d, area_len, count, iter, stride);
            stats[do_log][do_service] = tasvir_sync_stats_get();
        }
    }
    for (do_log = 0; do_log < 2; do_log++)
        for (do_service = 0; do_service < 2; do_service++) {
            fprintf(stderr, "   log%c service%c: %5ld ms (sync: count=%5ld, time_ms=%5ld, size=%9ldkB)\n",
                    do_log ? '+' : '-', do_service ? '+' : '-', time_ms[do_log][do_service],
                    stats[do_log][do_service].count, stats[do_log][do_service].cumtime_us / 1000,
                    stats[do_log][do_service].cumbytes / 1000);
        }
    fprintf(stderr, "\n");
    double overhead_service, overhead_sync, overhead_log, overhead_direct, overhead_indirect, overhead_full;
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

    return 0;
}
