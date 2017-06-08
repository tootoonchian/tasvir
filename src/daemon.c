#include <assert.h>
#include <errno.h>
#include <rte_cycles.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tasvir.h"

void usage(char *exec) { fprintf(stderr, "usage: %s root|daemon core\n", exec); }

int main(int argc, char **argv) {
    if (argc != 3) {
        usage(argv[0]);
        return -1;
    }

    char *role = argv[1];
    int core = atoi(argv[2]);
    bool is_root = strcmp(role, "root") == 0;
    bool is_daemon = strcmp(role, "daemon") == 0;

    if (!(is_root || is_daemon)) {
        usage(argv[0]);
        return -1;
    }

    tasvir_area_desc *root_desc = tasvir_init(core, is_root ? TASVIR_THREAD_TYPE_ROOT : TASVIR_THREAD_TYPE_DAEMON);
    if (root_desc == MAP_FAILED) {
        fprintf(stderr, "tasvir_daemon: tasvir_init_daemon failed\n");
        return -1;
    }

    while (true) {
        tasvir_service();
        rte_delay_us_block(10);
    };

    return 0;
}
