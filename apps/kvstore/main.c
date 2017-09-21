#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "alloc.h"
#include "alloc_dict.h"
#include "tasvir.h"
#define __unused __attribute__((__unused__))
/*#define _ALLOC_TEST_*/
#define CONSISTENCY 0
/*#define CONSISTENCY 1*/

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
#define MAX_CORES 4
struct kv_test {
    int id;
    int servers;
    char *access_log;
    char *load_log;
    int cores[MAX_CORES];
    int ncores;
};

enum kvop {
    GET,
    UPDATE
};

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

static void parse_cores(char* core_string, struct kv_test *out) {
    char *next = strtok(core_string, ",");
    out->ncores = 0;
    do {
        out->cores[out->ncores++] = atoi(next);
    } while (out->ncores < MAX_CORES && (next = strtok(NULL, ",")) != NULL);
}

int parse_args(int argc, char* argv[], struct kv_test *out) {
    int c;
    while((c = getopt(argc, argv, "s:n:a:l:c:")) != -1) {
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
                break;
                /*printf("Load log is at %s\n", load_log);*/
            case 'c':
                parse_cores(optarg, out);
                break;
        }
    }
    return 1;
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

inline void update(dictWrapper *w, char *key, char *value) {
    char *dictKey = allocKey(w, key);
    void *dictVal = allocVal(w, value, strlen(value));
#if CONSISTENCY
    printf("wrote \"%s\"\n", key);
#endif
    dictReplace(w->d, dictKey, dictVal);
}

inline void get(dictWrapper *w, char *key) {
    dictEntry *de;
    int len = strlen(key);
    if(key[len-1] == '\n') {
        key[len-1] = 0;
    }
    de = dictFind(w->d, key);
#if CONSISTENCY
    if (de != NULL) {
        printf("%s %s\n", key, de->v.val);
    } else {
        printf("not found \"%s\"\n", key);
    }
#endif
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

struct operation *parse_load_file(struct kv_test *args) {
    return parse_file(args->load_log);
}

struct operation *parse_access_file(struct kv_test *args) {
    return parse_file(args->access_log);
}

void load_data(int id, struct operation *loads, dictWrapper *w) {
    struct operation *current = loads;
    while (current) {
        assert(current->op == UPDATE);
        if (current->server == id) {
            update(w, current->key, current->value);
        }
        current = current->next;
        tasvir_service();
    }
}

void run_access(int id, struct operation *acs, dictWrapper *w[], __unused size_t servers) {
    struct operation *current = acs;
    while (current) {
        if (current->op == UPDATE) {
            if (current->server == id) {
                update(w[id], current->key, current->value);
            }
        } else if (current->op == GET) {
#if CONSISTENCY
            struct timespec current_time = {0, 0};
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            printf("%lu %lu ", current_time.tv_sec, current_time.tv_nsec);
#endif
            get(w[current->server], current->key);
        }
        current = current->next;
        wrap_service();
    }
}

// KEY SIZE is 64
const  size_t KEY_SIZE = 64;
// VALUE SIZE is 256
const size_t VALUE_SIZE = 256;

// FIXME: What units is this size in? I think it is in GB, cannot allocate 2 GB, not sure why.
// Set up a 2GB area
const size_t AREA_SIZE = 1ull * 1024ull * 1024ull * 1024ull;
/*const size_t AREA_SIZE = 100 * 1024 * 1024;*/
const size_t REGION_SIZE = 250ull * 1024ull * 1024ull;

struct thread_init {
    int id;
    int core;
    int servers;
    struct operation *load_log;
    struct operation *access_log;
};

inline void cpu_relax() {
    __asm__ __volatile__ ("rep; nop" : : : "memory");
}


#define MAX_SERVERS 4
inline tasvir_area_desc *subscribe_region(char* area_name, tasvir_area_desc *root) {
    tasvir_area_desc *remote;
    while ((remote = tasvir_attach(root, area_name, NULL)) == MAP_FAILED) {
        tasvir_service(); // Not wrapped since there is no way around this.
        cpu_relax();
    }
    return remote;
}

static inline void await_barrier(uint64_t *var, const uint64_t val) {
    while (*var != val) {
        tasvir_service();
        cpu_relax();
    }
}

inline void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result) {
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

static void *thread_code(void *init_struct) {
    struct thread_init *args = (struct thread_init*)init_struct;
    tasvir_area_desc param;
    tasvir_area_desc param_lock;
    tasvir_area_desc *d[MAX_SERVERS] = {NULL};
    tasvir_area_desc *l[MAX_SERVERS] = {NULL}; // Used for barrier
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
    dictWrapper *w[MAX_SERVERS] = {NULL};
    uint64_t *locks[MAX_SERVERS] = {NULL};
    int i = 0;
#if 0 // CLANG does not like pthread_set_affinity_np
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();
    int ret = 0;
    CPU_ZERO(&cpuset);
    CPU_SET(args->core, &cpuset);
    ret = pthread_set_affinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        printf("Could not set affinity %d\n", ret);
    }
#endif
    printf("Running id %d on core %d\n", args->id, args->core);

    /* Step 0: Initialize our bit */
    root_desc = tasvir_init(TASVIR_THREAD_TYPE_APP, args->core, NULL);
    if (root_desc == MAP_FAILED) {
        printf("test_ctrl: tasvir_init failed\n");
        return NULL;
    }
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = AREA_SIZE;
    // Naming based on ID, not sure if this is reasonable.
    snprintf(area_name, 32, "kvs%d", args->id);
    strcpy(param.name, area_name);
    d[args->id] = tasvir_new(param, 0); // Created a region.
    assert(d[args->id] != MAP_FAILED);
    data = d[args->id]->h->data;
    dict = data;
    entry = (void *)(data + REGION_SIZE);
    key = (void *)(data +  2ull * REGION_SIZE);
    val = (void *)(data + 3ull * REGION_SIZE);
    w[args->id] = initDictWrapper(dict, REGION_SIZE, entry, REGION_SIZE, key, KEY_SIZE, REGION_SIZE,
                val, VALUE_SIZE, REGION_SIZE);
    printf("Created dictionary\n");
    // Get locks
    snprintf(area_name, 32, "lck%d", args->id);
    strcpy(param_lock.name, area_name);
    param_lock.pd = root_desc;
    param_lock.owner = NULL;
    param_lock.type = TASVIR_AREA_TYPE_APP;
    param_lock.len = 4 * sizeof(uint64_t);
    l[args->id] = tasvir_new(param_lock, 0);

    assert(l[args->id] != MAP_FAILED);
    locks[args->id] = (uint64_t *)l[args->id];
    printf("Created created lock\n");

    printf("Starting to load data\n");
    load_data(args->id, args->load_log, w[args->id]);
    printf("Done loading data\n");

    for (i = 0; i < args->servers; i++) {
        if (i == args->id) {
            continue; // We already know each other.
        }
        snprintf(area_name, 32, "kvs%d", i);
        d[i] = subscribe_region(area_name, root_desc);
        tasvir_service();
        w[i] = subscribeDict(d[i]->h->data); // Data is on top.
        printf("Successfully subscribed to dictionary region for %d\n", i);
        tasvir_service();

        snprintf(area_name, 32, "lck%d", i);
        l[i] = subscribe_region(area_name, root_desc);
        locks[i] = (uint64_t *)l[i];
        printf("Successfully subscribed to lock for %d\n", i);
        tasvir_service();
    }
    // Indicate we are ready
    *locks[args->id] = 1;
    for (i = 0; i < args->servers; i++) {
        if (i == args->id) {
            continue;
        }
        await_barrier(locks[i], 1);
        printf("%d barrier is released\n", i);
    }

    // FIXME: Synchronize here waiting for all the other servers to finish loading.
    // Begin measuring.
    clock_gettime(CLOCK_MONOTONIC, &start);
    run_access(args->id, args->access_log, w, args->servers);
    clock_gettime(CLOCK_MONOTONIC, &end);
    timespec_diff(&start, &end, &diff);
    printf("%d Done running operations took %lu sec %lu ns\n",
            args->id, diff.tv_sec, diff.tv_nsec);
    return NULL;
}

int main(int argc, char *argv[]) {

    struct kv_test args;
    /*int i = 0;*/
#if 0
    pthread_t thread[MAX_CORES];
#endif
    struct thread_init targs[MAX_CORES];
    struct operation *load_log = NULL;
    struct operation *access_log = NULL;
    __unused int ret = 0;

    args.ncores = 0;
    parse_args(argc, argv, &args);
    load_log = parse_load_file(&args);
    access_log = parse_access_file(&args);
    assert(load_log);
    assert(access_log);
    printf("Found %d cores\n", args.ncores);
#if 0 /* Multiprocess not multicore */
    for (int i = 0; i < args.ncores; i++) {
        printf("Launching %d %d\n", i, args.cores[i]);
        targs[i].id = i;
        targs[i].core = args.cores[i];
        targs[i].load_log = load_log;
        targs[i].access_log = access_log;
        ret = pthread_create(&thread[i], NULL, thread_code, &targs[i]);
        if (ret != 0) {
            printf("Error creating thread %d %d\n", i, ret);
        }
    }

    for (int i = 0; i < args.ncores; i++) {
        pthread_join(thread[i], NULL);
        printf("Joined with thread %d\n", i);
    }
    printf("Done\n");
#endif
    assert(args.servers <= MAX_SERVERS);
    targs[0].id = args.id;
    targs[0].core = args.cores[0];
    targs[0].load_log = load_log;
    targs[0].access_log = access_log;
    targs[0].servers = args.servers;
    thread_code(&targs[0]);
    free_operation_list(load_log);
    free_operation_list(access_log);
}
