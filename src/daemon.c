#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tasvir.h"

int
main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    if (tasvir_init_daemon(0)) {
        fprintf(stderr, "tasvir_daemon: tasvir_init_daemon failed\n");
        return -1;
    }

    while (true) {
        tasvir_sync_daemon();
        usleep(10);
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
