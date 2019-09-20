#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <tasvir/tasvir.h>

#include "alloc.h"
#include "alloc_dict.h"

#define MS2US (1000)
#define S2US (1000 * MS2US)
uint64_t siphash(const uint8_t *in, const size_t inlen, const uint8_t *k);
/*#define _ALLOC_TEST_*/
#define MAX_WORKERS 4
#define KEY_SIZE 12  //  16; // taken from redis bench*/
#define VALUE_SIZE 256

const size_t AREA_SIZE = 1ull * 1024ull * 1024ull * 1024ull;
const size_t REGION_SIZE = 250ull * 1024ull * 1024ull;

typedef struct kvpair_t {
    char k[KEY_SIZE];
    char v[VALUE_SIZE];
} kvpair_t;

struct kv_test {
    int wid;
    int nr_workers;
    char *access_log;
    char *load_log;
    int iterations;
    int data_size;
    int randomsize;
    int syncinterval;
};

struct results {
    uint64_t n_ops;
    uint64_t n_writes;
    uint64_t n_reads;
    uint64_t n_remote_writes;
};

enum kvop { GET, UPDATE };

void parse_args(int argc, char *argv[], struct kv_test *out) {
    int c;
    out->iterations = 1;
    while ((c = getopt(argc, argv, "s:n:a:l:i:d:r:")) != -1) {
        switch (c) {
        case 's':
            out->wid = atoi(optarg);
            /*printf("Server ID is %d\n", server_id);*/
            break;
        case 'n':
            out->nr_workers = atoi(optarg);
            /*printf("Num regions is %d\n", nr_workers);*/
            break;
        case 'a':
            out->access_log = optarg;
            /*printf("Access log is at %s\n", access_log);*/
            break;
        case 'l':
            out->load_log = optarg;
            /*printf("Load log is at %s\n", load_log);*/
            break;
        case 'i':
            out->iterations = atoi(optarg);
            break;
        case 'd':
            out->data_size = atoi(optarg);
            if (out->data_size > VALUE_SIZE) {
                out->data_size = VALUE_SIZE - 1;
            }
            if (out->data_size <= 0) {
                out->data_size = 1;
            }
            break;
        case 'r':
            out->randomsize = atoi(optarg);
            if (out->randomsize < 0) {
                out->randomsize = 0;
            }
            break;
        }
    }
}

int update(dictWrapper *w, char *key, char *value) {
    char *dictKey = allocKey(w, key);
    void *dictVal = allocVal(w, value, strlen(value));
#if CONSISTENCY
    printf("wrote \"%s\"\n", key);
#endif
    dictReplace(w->d, dictKey, dictVal);
    return 0;
}

int update_byval(dictWrapper *w, kvpair_t kv) { return update(w, kv.k, kv.v); }
TASVIR_RPCFN_DEFINE(update_byval, TASVIR_FN_NOACK, int, dictWrapper *, kvpair_t)

inline dictEntry *get(dictWrapper *w, char *key) {
    dictEntry *de;
    int len = strlen(key);
    if (key[len - 1] == '\n') {
        key[len - 1] = 0;
    }
    de = dictFind(w->d, key);
#if CONSISTENCY
    if (de != NULL) {
        printf("%s %s\n", key, de->v.val);
    } else {
        printf("not found \"%s\"\n", key);
    }
#endif
    return de;
}

inline void cpu_relax() { __asm__ __volatile__("rep; nop" : : : "memory"); }

static inline void await_barrier(uint64_t *var, const uint64_t val) {
    while (*var != val) {
        tasvir_service();
        cpu_relax();
    }
}

inline void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result) {
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

static inline uint32_t fast_random() {
    static uint64_t seed = 42;
    seed = seed * 1103515245 + 12345;
    return seed >> 32;
}

void random_get(int randomsize, dictWrapper *w[], size_t nr_workers) {
    char key[KEY_SIZE];
    size_t r = fast_random() % randomsize;
    for (size_t i = 0; i < KEY_SIZE - 1; i++) {
        key[i] = '0' + r % 10;
        r /= 10;
    }
    key[KEY_SIZE - 1] = '\0';
    uint64_t h = siphash((uint8_t *)key, KEY_SIZE, (uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ") % nr_workers;
    get(w[h], key);
}

void random_update(int randomsize, struct kvpair_t kv, dictWrapper *w[], tasvir_area_desc *d[], size_t nr_workers,
                   size_t id) {
    size_t r = fast_random() % randomsize;
    for (size_t i = 0; i < KEY_SIZE - 1; i++) {
        kv.k[i] = '0' + r % 10;
        r /= 10;
    }
    kv.k[KEY_SIZE - 1] = '\0';
    uint64_t h = siphash((uint8_t *)kv.k, KEY_SIZE, (uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ") % nr_workers;
    if (id == h) {
        update(w[id], kv.k, kv.v);
    } else {
        tasvir_rpc(d[h], (tasvir_fnptr)&update_byval, w[h], kv);
    }
}

int main(int argc, char *argv[]) {
    struct kv_test args;
    args.data_size = 4;
    // Parametrize better
    args.syncinterval = 5;
    parse_args(argc, argv, &args);
    args.data_size = 4;
    struct kvpair_t kv;
    for (int i = 0; i < args.data_size; i++) {
        kv.v[i] = '0';
    }
    kv.v[args.data_size - 1] = '\0';

    tasvir_area_desc param = {0};
    tasvir_area_desc param_lock = {0};
    tasvir_area_desc *d[MAX_WORKERS] = {NULL};
    tasvir_area_desc *l[MAX_WORKERS] = {NULL};  // Used for barrier
    tasvir_area_desc *root_desc = NULL;
    char area_name[32];
    uint8_t *data = NULL;
    void *dict = NULL;
    void *entry = NULL;
    void *key = NULL;
    void *val = NULL;
    struct timespec start = {0, 0};
    struct timespec end = {0, 0};
    struct timespec diff = {0, 0};
    dictWrapper *w[MAX_WORKERS] = {NULL};
    uint64_t *locks[MAX_WORKERS] = {NULL};
    int i = 0;

    printf("Running wid %d\n", args.wid);

    /* Step 0: Initialize our bit */
    root_desc = tasvir_init();
    if (!root_desc) {
        printf("test_ctrl: tasvir_init failed\n");
        return 1;
    }

    // Reigster for RPC
    TASVIR_RPCFN_REGISTER(update_byval);

    param.pd = root_desc;
    param.len = AREA_SIZE;
    param.sync_int_us = 10000;
    param.sync_ext_us = 100000;
    if (args.wid == 0) {
        // Naming based on ID
        snprintf(area_name, 32, "kvs%d", args.wid);
        strcpy(param.name, area_name);
        d[args.wid] = tasvir_new(param);  // Created a region.
        assert(d[args.wid]);
        data = tasvir_data(d[args.wid]);
        dict = data;
        entry = (void *)(data + REGION_SIZE);
        key = (void *)(data + 2ull * REGION_SIZE);
        val = (void *)(data + 3ull * REGION_SIZE);
        w[args.wid] = initDictWrapper(dict, REGION_SIZE, entry, REGION_SIZE, key, KEY_SIZE, REGION_SIZE, val,
                                      args.data_size, REGION_SIZE);
        printf("Created dictionary, syncing\n");

        // Get locks
        snprintf(area_name, 32, "lck%d", args.wid);
        strcpy(param_lock.name, area_name);
        param_lock.pd = root_desc;
        param_lock.len = 4 * sizeof(uint64_t);
        param_lock.sync_int_us = 10000;
        param_lock.sync_ext_us = 100000;
        l[args.wid] = tasvir_new(param_lock);

        assert(l[args.wid]);
        locks[args.wid] = (uint64_t *)tasvir_data(l[args.wid]);
        printf("Created created lock %s\n", area_name);
    }


    for (i = 0; i < 1; i++) {
        if (i == args.wid) {
            continue;  // We already know ourselves.
        }
        snprintf(area_name, 32, "kvs%d", i);
        d[i] = tasvir_attach_wait(5 * S2US, area_name);
        w[i] = subscribeDict(tasvir_data(d[i]));  // Data is on top.
        printf("Successfully subscribed to dictionary region for %d\n", i);
        printf("Trying to subscribe to lock for %d\n", i);
        snprintf(area_name, 32, "lck%d", i);
        l[i] = tasvir_attach_wait(5 * S2US, area_name);
        locks[i] = (uint64_t *)tasvir_data(l[i]);
        printf("Successfully subscribed to lock for %d %lx\n", i, (uint64_t)locks[i]);
    }

    // Indicate we are ready
    if (args.wid == 0) {
        *locks[args.wid] = 1;
        tasvir_log(locks[args.wid], sizeof(uint64_t));
        printf("Updated lock %lx\n", (uint64_t)locks[args.wid]);
    }

    for (i = 0; i < 1; i++) {
        if (i == args.wid) {
            continue;
        }
        await_barrier(locks[i], 1);
        printf("%d barrier is released\n", i);
    }

    printf("Starting run \n");
    uint64_t get = 0, put = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < args.iterations; i++) {
        random_get(args.randomsize, w, 1);
        get++;
        if (args.wid == 0) {
            random_update(args.randomsize, kv, w, d, 1, 0);
            put++;
        }
        if (i % args.syncinterval == 0) {
            tasvir_service();
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    timespec_diff(&start, &end, &diff);
    printf("%d Done running operations took %lu sec %lu us %lu gets %lu put\n", args.wid, diff.tv_sec,
           diff.tv_nsec / 1000, get, put);

    return 0;
}
