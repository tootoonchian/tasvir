#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tasvir.h"

int
main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    tasvir_area_desc *root_desc = tasvir_init(1, TASVIR_INSTANCE_TYPE_ROOT);
    if (!root_desc) {
        fprintf(stderr, "tasvir_daemon: tasvir_init_daemon failed\n");
        return -1;
    }

    struct timespec ts = {0, 50000};
    while (true) {
        tasvir_sync();
        nanosleep(&ts, NULL);
        tasvir_rpc_serve();
    };

    /*
    struct tasvir_area area;
    if (tasvir_attach("meta", 4096, &area))
        return -1;
    if (tasvir_detach(&area))
        return -1;

    int *a = malloc(sizeof(int));
    *a = 10;
    */

    return 0;
}
