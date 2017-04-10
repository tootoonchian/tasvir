#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "tasvir.h"

int
main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    tasvir_area_desc *root_desc = tasvir_init(1, TASVIR_INSTANCE_TYPE_APP);
    if (root_desc == MAP_FAILED) {
        fprintf(stderr, "test_ctrl: tasvir_init failed\n");
        return -1;
    }

    tasvir_area_desc *d = tasvir_new(root_desc, NULL, TASVIR_AREA_TYPE_APP, "test", 10 * 1024 * 1024, 5000, 128);
    assert(d);

    // assert(tasvir_delete(d) == 0);

    return 0;
}
