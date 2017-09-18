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
#define CONSISTENCY 1

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
#ifndef CONSISTENCY
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
#ifndef CONSISTENCY
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

void load_data(struct kv_test *args, struct operation *loads, dictWrapper *w) {
    struct operation *current = loads;
    while (current) {
        assert(current->op == UPDATE);
        if (current->server == args->id) {
            update(w, current->key, current->value);
        }
        current = current->next;
        tasvir_service();
    }
}

void run_access(struct kv_test *args, struct operation *acs, dictWrapper *w) {
    struct operation *current = acs;
    while (current) {
        if (current->op == UPDATE) {
            if (current->server == args->id) {
                update(w, current->key, current->value);
            }
        } else if (current->op == GET) {
#ifndef CONSISTENCY
            struct timespec current_time = {0, 0};
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            printf("%lu %lu ", current_time.tv_sec, current_time.tv_nsec);
#endif
            get(w, current->key);
        }
        current = current->next;
        tasvir_service();
    }
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
    const size_t REGION_SIZE = 250ull * 1024ull * 1024ull;

    struct kv_test args;

    tasvir_area_desc param;
    tasvir_area_desc *d = NULL;
    struct operation *load_log = NULL;
    struct operation *access_log = NULL;
    tasvir_area_desc *root_desc = NULL;
    char area_name[32];
    uint8_t *data = NULL;
    void *dict = NULL;
    void *entry = NULL;
    void *key = NULL;
    void *val = NULL;
    struct timespec start = {0, 0};
    struct timespec end = {0, 0};
    dictWrapper *w = NULL;

    parse_args(argc, argv, &args);
    load_log = parse_load_file(&args);
    access_log = parse_access_file(&args);
    assert(load_log);
    assert(access_log);

    root_desc = tasvir_init(TASVIR_THREAD_TYPE_APP, 0, NULL);

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
    data = d->h->data;
    dict = data;
    entry = (void *)(data + REGION_SIZE);
    key = (void *)(data +  2ull * REGION_SIZE);
    val = (void *)(data + 3ull * REGION_SIZE);
    w = initDictWrapper(dict, REGION_SIZE, entry, REGION_SIZE, key, KEY_SIZE, REGION_SIZE,
                val, VALUE_SIZE, REGION_SIZE);
    printf("Starting to load data\n");
    load_data(&args, load_log, w);
    printf("Done loading data\n");
    // FIXME: Synchronize here waiting for all the other servers to finish loading.
    // Begin measuring.
    clock_gettime(CLOCK_MONOTONIC, &start);
    run_access(&args, access_log, w);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("Done running operations took %lu sec %lu ns\n",
            end.tv_sec - start.tv_sec, end.tv_nsec - start.tv_nsec);
    free_operation_list(load_log);
    free_operation_list(access_log);

}
