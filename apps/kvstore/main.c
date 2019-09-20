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

#define __unused __attribute__((__unused__))
/*#define _ALLOC_TEST_*/
#define CONSISTENCY 0
/*#define CONSISTENCY 1*/
const size_t AREA_SIZE = 1ull * 1024ull * 1024ull * 1024ull;
const size_t REGION_SIZE = 250ull * 1024ull * 1024ull;


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
#define MAX_WORKERS 4

#define KEY_SIZE 64
#define VALUE_SIZE 256

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
};

struct results {
    uint64_t n_ops;
    uint64_t n_writes;
    uint64_t n_reads;
    uint64_t n_remote_writes;
};

enum kvop { GET, UPDATE };

struct operation {
    int server;
    enum kvop op;
    char *key;
    char *value;
    char *line;
    struct operation *next;
};

static inline void wrap_service() {
#if !(NO_SERVICE)
    tasvir_service();
#endif
}

void parse_args(int argc, char *argv[], struct kv_test *out) {
    int c;
    out->iterations = 1;
    while ((c = getopt(argc, argv, "s:n:a:l:i:")) != -1) {
        switch (c) {
        case 's':
            out->wid = atoi(optarg);
            break;
        case 'n':
            out->nr_workers = atoi(optarg);
            break;
        case 'a':
            out->access_log = optarg;
            break;
        case 'l':
            out->load_log = optarg;
            break;
        case 'i':
            out->iterations = atoi(optarg);
            break;
        }
    }
}

struct operation *parse_line(char *line, ssize_t len) {
    char *out, *op, *key;
    struct operation *entry = malloc(sizeof(struct operation));
    entry->next = NULL;
    line[len - 1] = 0;
    entry->line = line;
    out = strtok(line, " ");
    entry->server = atoi(out);
    op = strtok(NULL, " ");
    key = strtok(NULL, " ");
    if (strcmp(op, "UPDATE") == 0) {
        entry->op = UPDATE;
        entry->key = key;
        entry->value = strtok(NULL, " ");
    } else if (strcmp(op, "GET") == 0) {
        entry->op = GET;
        entry->key = key;
        entry->value = NULL;
    } else {
        free(entry);
        entry = NULL;
    }
    return entry;
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

struct operation *parse_file(char *path) {
    char *buf = NULL;
    ssize_t nread;
    size_t len = 0;
    struct operation *head = NULL;
    struct operation *current = NULL;
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        printf("Could not open %s\n", path);
        perror("fopen");
        return NULL;
    }
    while ((nread = getline(&buf, &len, file)) >= 0) {
        struct operation *parsed = NULL;
        buf[nread - 1] = 0;
        parsed = parse_line(buf, nread);
        if (parsed) {
            if (current) {
                current->next = parsed;
                current = parsed;
            } else {
                current = parsed;
                head = parsed;
            }
        }
        buf = NULL;
        len = 0;
    }
    return head;
}

void free_operation_list(struct operation *list) {
    while (list) {
        struct operation *temp = list;
        free(temp->line);
        list = list->next;
    }
}

void load_data(int id, struct operation *loads, tasvir_area_desc *d, dictWrapper *w) {
    printf("Starting to load data\n");
    tasvir_area_activate(d, false);
    tasvir_activate(false);
    struct operation *current = loads;
    while (current) {
        assert(current->op == UPDATE);
        if (current->server == id) {
            update(w, current->key, current->value);
        }
        current = current->next;
    }
    printf("Done loading data\n");
    tasvir_activate(true);
    tasvir_area_activate(d, true);
}

struct thread_init {
    int wid;
    int nr_workers;
    int iterations;
    struct operation *load_log;
    struct operation *access_log;
};

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

uint64_t run_access(int id, struct operation *acs, dictWrapper *w[], tasvir_area_desc *d[], __unused size_t nr_workers,
                    struct results *r) {
    uint64_t total = 0;
    struct operation *current = acs;
    if (id == 0) {
        while (true)
            wrap_service();
    }
    while (current) {
        if (current->op == UPDATE) {
            r->n_writes++;
            if (current->server == id) {
                update(w[id], current->key, current->value);
            } else {
                r->n_remote_writes++;
                struct kvpair_t kv;
                memcpy(&kv.k, current->key, KEY_SIZE);
                memcpy(&kv.v, current->value, VALUE_SIZE);
                tasvir_rpc(d[current->server], (tasvir_fnptr)&update_byval, w[current->server], kv);
            }
        } else if (current->op == GET) {
            r->n_reads++;
#if CONSISTENCY
            struct timespec current_time = {0, 0};
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            printf("%lu %lu ", current_time.tv_sec, current_time.tv_nsec);
#endif
            get(w[current->server], current->key);
        }
        current = current->next;
        r->n_ops++;

        wrap_service();
    }

    return total;
}

int main(int argc, char *argv[]) {
    struct kv_test args;
    parse_args(argc, argv, &args);
    assert(args.nr_workers <= MAX_WORKERS);

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
    printf("Running worker id %d\n", args.wid);

    /* Step 0: Initialize our bit */
    root_desc = tasvir_init();
    if (!root_desc) {
        printf("tasvir_init failed\n");
        return -1;
    }

    // Reigster for RPC
    TASVIR_RPCFN_REGISTER(update_byval);

    param.pd = root_desc;
    param.len = AREA_SIZE;
    param.sync_int_us = 10000;
    param.sync_ext_us = 100000;
    // Naming based on ID, not sure if this is reasonable.
    snprintf(area_name, 32, "kvs%d", args.wid);
    strcpy(param.name, area_name);
    d[args.wid] = tasvir_new(param);  // Created a region.
    assert(d[args.wid]);
    data = tasvir_data(d[args.wid]);
    dict = data;
    entry = (void *)(data + REGION_SIZE);
    key = (void *)(data + 2ull * REGION_SIZE);
    val = (void *)(data + 3ull * REGION_SIZE);
    w[args.wid] = initDictWrapper(dict, REGION_SIZE, entry, REGION_SIZE, key, KEY_SIZE, REGION_SIZE, val, VALUE_SIZE,
                                  REGION_SIZE);
    printf("Created dictionary\n");

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

    struct operation *load_log = parse_file(args.load_log);
    assert(load_log);
    struct operation *access_log = parse_file(args.access_log);
    assert(access_log);
    load_data(args.wid, load_log, d[args.wid], w[args.wid]);

    for (i = 0; i < args.nr_workers; i++) {
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
    *locks[args.wid] = 1;
    tasvir_log(locks[args.wid], sizeof(uint64_t));
    printf("Updated lock %lx\n", (uint64_t)locks[args.wid]);
    for (i = 0; i < args.nr_workers; i++) {
        if (i == args.wid) {
            continue;
        }
        await_barrier(locks[i], 1);
        printf("%d barrier is released\n", i);
    }

    printf("Starting run \n");
    // FIXME: Synchronize here waiting for all the other nr_workers to finish
    // loading. Begin measuring.
    clock_gettime(CLOCK_MONOTONIC, &start);
    uint64_t t = 0;
    struct results r;
    memset(&r, 0, sizeof(struct results));
    for (int i = 0; i < args.iterations; i++) {
        printf("Starting iteration\n");
        t += run_access(args.wid, access_log, w, d, args.nr_workers, &r);
        printf("Done with iteration\n");
        printf("%d ops %lu w %lu r %lu rw %lu\n", args.wid, r.n_ops, r.n_writes, r.n_reads, r.n_remote_writes);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    timespec_diff(&start, &end, &diff);
    printf("%d Done running operations took %lu sec %lu ns %lu ops\n", args.wid, diff.tv_sec, diff.tv_nsec, t);
    printf("%d ops %lu w %lu r %lu rw %lu\n", args.wid, r.n_ops, r.n_writes, r.n_reads, r.n_remote_writes);

    free_operation_list(load_log);
    free_operation_list(access_log);

    return 0;
}
