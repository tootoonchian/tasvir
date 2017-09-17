#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include "alloc.h"
#include "alloc_dict.h"
#include "tasvir.h"
#define __unused __attribute__((__unused__))
/*#define _ALLOC_TEST_*/

#ifdef _ALLOC_TEST_
struct Test {
    int64_t test[16];
};

void test_allocator() {
    const size_t BUFFER_SIZE = sizeof(struct Test) * 10 + sizeof(Allocator);
    uint8_t buffer[BUFFER_SIZE];
    Allocator *a = init_allocator(buffer, BUFFER_SIZE, sizeof(struct Test));
    for (int i = 0; i < 10; i++) {
        struct Test *t = (struct Test *)alloc_allocator(a);
        printf("Alloc %d\n", i);
        assert(t != NULL);
    }
    assert(alloc_allocator(a) == NULL);
    a = init_allocator(buffer, BUFFER_SIZE, sizeof(struct Test));
    for (int i = 0; i < 100; i++) {
        struct Test *t = (struct Test *)alloc_allocator(a);
        assert(t != NULL);
        free_allocator(a, t);
    }
}
#endif
struct kv_test {
    int id;
    int servers;
    char *access_log;
    char *load_log;
};

int parse_args(int argc, char* argv[], struct kv_test *out) {
    int c;
    while((c = getopt(argc, argv, "s:n:a:l:")) != -1) {
        switch (c) {
            case 's':
                out->id = atoi(optarg);
                /*printf("Server ID is %d\n", server_id);*/
                break;
            case 'n':
                out->servers = atoi(optarg);
                /*printf("Num regions is %d\n", nservers);*/
                break;
            case 'a':
                out->access_log = optarg;
                /*printf("Access log is at %s\n", access_log);*/
                break;
            case 'l':
                out->load_log = optarg;
                /*printf("Load log is at %s\n", load_log);*/
        }
    }
    return 1;
}

inline void update(dictWrapper *w, char *key, char *value) {
    char *dictKey = allocKey(w, key);
    void *dictVal = allocVal(w, value, strlen(value));
    printf("wrote \"%s\"\n", key);
    dictReplace(w->d, dictKey, dictVal);
    dictEntry *de = dictFind(w->d, key);
    assert(de != NULL);
}

inline void get(dictWrapper *w, char *key) {
    dictEntry *de;
    int len = strlen(key);
    if(key[len-1] == '\n') {
        key[len-1] = 0;
    }
    de = dictFind(w->d, key);
    if (de != NULL) {
        printf("%s %s\n", key, de->v.val); 
    } else {
        printf("not found \"%s\"\n", key);
    }
}

void read_load(struct kv_test *args, dictWrapper *w) {
    FILE *file = fopen(args->load_log, "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }
    char *buf = NULL;
    ssize_t nread;
    size_t len = 0;
    while ((nread = getline(&buf, &len, file)) > 0) {
        buf[nread - 1] = 0;
        char *out = strtok(buf, " ");
        int server = atoi(out);
        if (server != args->id) {
            continue;
        }
        char *op = strtok(NULL, " ");
        char *key = strtok(NULL, " ");
        char *value = strtok(NULL, " ");
        assert(strcmp(op, "UPDATE") == 0);
        update(w, key, value);
    }
    tasvir_service();
    free(buf);
}

void read_access(struct kv_test *args, dictWrapper *w) {
    FILE *file = fopen(args->access_log, "r");
    struct timespec start = {0, 0}, current = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (file == NULL) {
        perror("fopen");
        return;
    }
    char *buf = NULL;
    ssize_t nread;
    size_t len = 0;
    while ((nread = getline(&buf, &len, file)) > 0) {
        buf[nread - 1] = 0;
        char *out = strtok(buf, " ");
        int server = atoi(out);
        char *op = strtok(NULL, " ");
        char *key = strtok(NULL, " ");
        if (strcmp(op, "UPDATE") == 0) {
            if (server != args->id) {
                continue;
            }
            char *value = strtok(NULL, " ");
            update(w, key, value);
        } else if (strcmp(op, "GET") == 0) {
            // FIXME: Sample this when testing throughput, reading clock is slow.
            clock_gettime(CLOCK_MONOTONIC, &current);
            printf("%lu %lu ", current.tv_sec - start.tv_sec, current.tv_nsec- start.tv_nsec);
            // FIXME: Use server to select correct w
            get(w, key);
        }
        tasvir_service();
    }
    free(buf);
}

int main(int argc, char *argv[]) {
    // KEY SIZE is 64
    const  size_t KEY_SIZE = 64;
    // VALUE SIZE is 256
    const size_t VALUE_SIZE = 256;

    // FIXME: What units is this size in? I think it is in GB, cannot allocate 2 GB, not sure why.
    // Set up a 2GB area
    const size_t AREA_SIZE = 1ull * 1024ull * 1024ull * 1024ull;
    /*const size_t AREA_SIZE = 100 * 1024 * 1024;*/

    struct kv_test args;

    tasvir_area_desc param;
    tasvir_area_desc *d = NULL;
    tasvir_area_desc *root_desc = tasvir_init(TASVIR_THREAD_TYPE_APP, 0, NULL);

    char area_name[32];
    parse_args(argc, argv, &args);
    if (root_desc == MAP_FAILED) {
        printf("test_ctrl: tasvir_init failed\n");
        return -1;
    }
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = AREA_SIZE;

    // Naming based on ID, not sure if this is reasonable.
    snprintf(area_name, 32, "kvs%d", args.id);
    strcpy(param.name, area_name);
    d = tasvir_new(param, 0);
    // FIXME: Need to register other wrappers, really not sure how one does that

    // FIXME: Change these sizes to be real once 2G is fixed.
    assert(d != MAP_FAILED);
    uint8_t *data = d->h->data;
    void *dict = data;
    const size_t REGION_SIZE = 250ull * 1024ull * 1024ull;
    void *entry = (void *)(data + REGION_SIZE);
    void *key = (void *)(data +  2ull * REGION_SIZE);
    void *val = (void *)(data + 3ull * REGION_SIZE);
    dictWrapper *w =
        initDictWrapper(dict, REGION_SIZE, entry, REGION_SIZE, key, KEY_SIZE, REGION_SIZE, 
                val, VALUE_SIZE, REGION_SIZE);
    read_load(&args, w);
    // FIXME: Synchronize here waiting for all the other servers to finish loading.
    read_access(&args, w);

}
