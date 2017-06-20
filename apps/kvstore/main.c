#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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

int main(__unused int argc, __unused char *argv[]) {
    tasvir_area_desc param;
    tasvir_area_desc *d = NULL;
    tasvir_area_desc *root_desc = tasvir_init(0, TASVIR_THREAD_TYPE_APP);
    size_t area_size = 4 * 1024 * 1024;
    if (root_desc == MAP_FAILED) {
        printf("test_ctrl: tasvir_init failed\n");
        return -1;
    }
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = area_size;
    strcpy(param.name, "test");
    d = tasvir_new(param, 5000, 0);
    assert(d != MAP_FAILED);
    uint8_t *data = d->h->data;
    void *dict = data;
    void *entry = (void *)(data + 1024 * 1024);
    void *key = (void *)(data + 2 * 1024 * 1024);
    void *val = (void *)(data + 3 * 1024 * 1024);
    dictWrapper *w =
        initDictWrapper(dict, 1024 * 1024, entry, 1024 * 1024, key, 128, 1024 * 1024, val, 128, 1024 * 1024);
    assert(w != NULL);
    tasvir_service();

    char *dictKey = (char *)alloc_allocator(w->keyAllocator);
    tasvir_log_write(w->keyAllocator, sizeof(Allocator));

    strcpy(dictKey, "Hellooooo");
    tasvir_log_write(dictKey, strlen(dictKey) + 1);

    char *dictVal = (char *)alloc_allocator(w->valAllocator);
    tasvir_log_write(w->valAllocator, sizeof(Allocator));

    strcpy(dictVal, "World");
    tasvir_log_write(dictVal, strlen(dictKey) + 1);

    dictAdd(w->d, dictKey, dictVal);
    tasvir_log_write(w->d->ht[0].table, w->d->ht[0].size * sizeof(dictEntry*));
    struct dictEntry *de = dictFind(w->d, "Hellooooo");
    tasvir_log_write(de, sizeof(dictEntry));
    assert(de != NULL);
    
    printf("Found value %s\n", de->v.val);
    dictDelete(w->d, "Hellooooo");
    tasvir_log_write(w->d->ht[0].table, w->d->ht[0].size * sizeof(dictEntry*));
    tasvir_log_write(de, sizeof(dictEntry));
    tasvir_log_write(w->keyAllocator, sizeof(Allocator));
    tasvir_log_write(w->valAllocator, sizeof(Allocator));

    de = dictFind(w->d, "Hellooooo");
    assert(de == NULL);

    printf("OK, this builds\n");
    while (true) {
        tasvir_service();
    }
#ifdef _ALLOC_TEST_
    test_allocator();
    printf("OK, test passes\n");
#endif
}
