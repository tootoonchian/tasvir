#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "tasvir.h"

int
main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    if (tasvir_init(1)) {
        fprintf(stderr, "test_ctrl: tasvir_init failed\n");
        return -1;
    }

    tasvir_meta *meta = tasvir_new("test", 10 * 1024 * 1024);
    if (meta == MAP_FAILED) {
        fprintf(stderr, "test_ctrl: tasvir_new failed\n");
        return -1;
    }

    tasvir_area *area = tasvir_area_new(meta, "amin", 1000);
    if (area == NULL) {
        fprintf(stderr, "test_ctrl: tasvir_area_new failed\n");
        return -1;
    }

    if (tasvir_delete(meta)) {
        fprintf(stderr, "test_ctrl: tasvir_delete failed\n");
        return -1;
    }

    return 0;
}
