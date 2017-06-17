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

uint64_t gettime_us() { return 1E6 * rte_rdtsc() / rte_get_tsc_hz(); }

uint64_t experiment(tasvir_area_desc *d, int count, int iter, int stride) {
    uint64_t time_us = gettime_us();
    int i;
    while (count > 0) {
        count -= iter;
        i = iter;
        while (i--)
            random_write(d->h->data, d->len - 4096, stride);
        if (do_service)
            tasvir_service();
    }
    return (gettime_us() - time_us) / 1000;
}

void flush_cache() {
    int fd = open("/lib/modules/4.10.0-rc1+/updates/dkms/wbinvd.ko", O_RDONLY | O_CLOEXEC);
    if (!fd) {
        return;
    }

    syscall(__NR_finit_module, fd, "", 0);
    syscall(__NR_delete_module, "wbinvd", 0);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s core nr_updates nr_updates_per_service area_bytes stride\n", argv[0]);
        return -1;
    }
    int core = atoi(argv[1]);
    int count = atoi(argv[2]);
    int iter = atoi(argv[3]);
    size_t area_len = atol(argv[4]);
    int stride = atoi(argv[5]);

    init();

    tasvir_area_desc *root_desc = tasvir_init(core, TASVIR_THREAD_TYPE_APP);
    if (root_desc == MAP_FAILED) {
        cerr << argv[0] << ": tasvir_init failed" << std::endl;
        return -1;
    }

    tasvir_area_desc param;
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = area_len;
    strcpy(param.name, "test");
    tasvir_area_desc *d = tasvir_new(param, 5000, 0);
    if (d == MAP_FAILED) {
        cerr << argv[0] << ": tasvir_new failed" << std::endl;
        return -1;
    }

    /*
    do_service = do_log = true;
    fprintf(stderr, "took %ld msecs\n", experiment(d, count, iter, stride));
    return 0;
    */

    uint64_t time_ms[4];
    for (do_service = 1; do_service >= 0; do_service--)
        for (do_log = 1; do_log >= 0; do_log--) {
            flush_cache();
            fprintf(stderr, "   log%c service%c\n", do_log ? '+' : '-', do_service ? '+' : '-');
            time_ms[do_log * 2 + do_service] = experiment(d, count, iter, stride);
        }
    for (do_log = 0; do_log < 2; do_log++)
        for (do_service = 0; do_service < 2; do_service++)
            fprintf(stderr, "   log%c service%c: %5ld ms\n", do_log ? '+' : '-', do_service ? '+' : '-',
                    time_ms[do_log * 2 + do_service]);
    double overhead;
    overhead = 100. * ((long)time_ms[1] - (long)time_ms[0]) / time_ms[0];
    fprintf(stderr, "service overhead: %5.2f%%\n", overhead > 0 ? overhead : 0);
    overhead = 100. * ((long)time_ms[2] - (long)time_ms[0]) / time_ms[0];
    fprintf(stderr, "    log overhead: %5.2f%%\n", overhead > 0 ? overhead : 0);
    overhead = 100. * ((long)time_ms[3] - (long)time_ms[0]) / time_ms[0];
    fprintf(stderr, "   full overhead: %5.2f%%\n", overhead > 0 ? overhead : 0);

    return 0;
}
