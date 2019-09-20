#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <iostream>

#include <tasvir/tasvir.h>

int main(int argc, char **argv) {
    constexpr int KB = 1024;
    constexpr int S2US = 1000 * 1000;
    constexpr int nr_workers_max = 256;

    if (argc != 6) {
        std::cerr << "usage: " << argv[0] << " wid nr_workers count_to sync_internal_us sync_external_us" << std::endl;
        return -1;
    }
    int my_wid = atoi(argv[1]);
    int nr_workers = atoi(argv[2]);
    int count_to = atoi(argv[3]);
    uint64_t sync_int_us = atol(argv[4]);
    uint64_t sync_ext_us = atol(argv[5]);
    if (nr_workers > nr_workers_max) {
        std::cerr << "nr_workers must be less than " << nr_workers_max << std::endl;
        return -1;
    }
    if (!tasvir_init()) {
        std::cerr << "tasvir_init failed" << std::endl;
        return -1;
    }

    std::cout << "wid=" << my_wid << " nr_workers=" << nr_workers << " count_to=" << count_to
              << " sync_int_us=" << sync_int_us << " sync_ext_us=" << sync_ext_us << std::endl;

    tasvir_area_desc param = {};
    param.len = 1 * KB;
    param.sync_int_us = sync_int_us;
    param.sync_ext_us = sync_ext_us;

    int *counter[nr_workers_max];

    for (int wid = 0; wid < nr_workers; wid++) {
        snprintf(param.name, sizeof(param.name), "counter-%04x", wid);
        tasvir_area_desc *d = my_wid == wid ? tasvir_new(param) : tasvir_attach_wait(5 * S2US, param.name);
        if (!d) {
            std::cerr << "creation/attach to " << param.name << " failed" << std::endl;
            return -1;
        }
        counter[wid] = (int *)tasvir_data(d);
        std::cout << "worker " << wid << " counter @" << counter[wid] << std::endl;
    }

    // doing two repetitions to start the timer at the same time for all processes
    for (int rep = 0; rep < 2; rep++) {
        int count_to2 = rep == 0 ? 1 : count_to;
        auto start = std::chrono::steady_clock::now();
        for (int count = 1 + rep; count <= count_to2 + rep; count++) {
            *counter[my_wid] = count;
            tasvir_log(counter[my_wid], sizeof(int));
            for (int wid = 0; wid < nr_workers; wid++)
                while (*counter[wid] < count)
                    tasvir_service();
            // Every thread is at step count
        }
        if (rep == 1) {
            auto duration =
                std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
            printf("nr_workers=%d sync_int_us=%lu sync_ext_us=%lu time_us=%lu", nr_workers, sync_int_us, sync_ext_us,
                   duration.count() / count_to);
        }
    }
    // make sure your last write is visible before exiting
    while (tasvir_service())
        _mm_pause();

    return 0;
}
