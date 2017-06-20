#include "alloc_dict.h"
#include <string.h>
#define __unused __attribute__((__unused__))
static void keyDestructor(void *privdata, void *key) {
    Allocator *a = ((dictWrapper *)privdata)->keyAllocator;
    free_allocator(a, key);
}

static void valDestructor(void *privdata, void *key) {
    Allocator *a = ((dictWrapper *)privdata)->valAllocator;
    free_allocator(a, key);
}

static uint64_t hashCallback(const void *key) { return dictGenHashFunction((char *)key, strlen((char *)key)); }

static int compareCallback(__unused void *privdata, const void *key1, const void *key2) {
    int l1, l2;
    l1 = strlen((const char *)key1);
    l2 = strlen((const char *)key2);
    if (l1 != l2)
        return 0;
    return memcmp(key1, key2, l1) == 0;
}

dictType AllocDictType = {hashCallback, NULL, NULL, compareCallback, keyDestructor, valDestructor};

dictWrapper *initDictWrapper(void *space, size_t len, void *entrySpace, size_t entrySize, void *keySpace, size_t keyLen,
                             size_t keySize, void *valSpace, size_t valLen, size_t valSize) {
    dictWrapper *wrapper = (dictWrapper *)space;
    wrapper->entryAllocator = init_allocator(entrySpace, entrySize, sizeof(dictEntry));
    wrapper->keyAllocator = init_allocator(keySpace, keySize, keyLen);
    wrapper->valAllocator = init_allocator(valSpace, valSize, valLen);
    void *dspace = (void *)(((intptr_t)space) + sizeof(dictWrapper));
    wrapper->d = dictCreate(&AllocDictType, wrapper, dspace, len - sizeof(dictWrapper), wrapper->entryAllocator);
    return wrapper;
}
