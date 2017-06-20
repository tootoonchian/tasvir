#include "alloc_dict.h"
#include "tasvir.h"
#include <string.h>
#define __unused __attribute__((__unused__))
static void keyDestructor(void *privdata, void *key) {
    Allocator *a = ((dictWrapper *)privdata)->keyAllocator;
    free_allocator(a, key);
    tasvir_log_write(a, sizeof(Allocator));
    tasvir_log_write(key, a->alloc_size);
}

static void valDestructor(void *privdata, void *key) {
    Allocator *a = ((dictWrapper *)privdata)->valAllocator;
    free_allocator(a, key);
    tasvir_log_write(a, sizeof(Allocator));
    tasvir_log_write(key, a->alloc_size);
}

static uint64_t hashCallback(const void *key) { return dictGenHashFunction((char *)key, strlen((char *)key)); }

static void entryDestructor(void *privdata, dictEntry *e) {
    Allocator *a = ((dictWrapper *)privdata)->entryAllocator;
    free_allocator(a, e);
    tasvir_log_write(a, sizeof(Allocator));
    tasvir_log_write(e, a->alloc_size);
}

static dictEntry *entryConstructor(void *privdata) {
    Allocator *a = ((dictWrapper *)privdata)->entryAllocator;
    dictEntry* entry =  (dictEntry *)alloc_allocator(a);
    tasvir_log_write(a, sizeof(Allocator));
    tasvir_log_write(entry, sizeof(dictEntry));
    return entry;
}

static void entryModed(__unused void *privdata, dictEntry **entry) {
    tasvir_log_write(entry, sizeof(dictEntry*));
}

char *allocKey(dictWrapper *w, const char *key) {
    char *dictKey = (char*)alloc_allocator(w->keyAllocator);
    tasvir_log_write(w->keyAllocator, sizeof(Allocator));

    strcpy(dictKey, key);
    tasvir_log_write(dictKey, strlen(dictKey));
    return dictKey;
}

void *allocVal(dictWrapper *w, void *val, size_t len) {
    void *dictVal = alloc_allocator(w->valAllocator);
    tasvir_log_write(w->valAllocator, sizeof(Allocator));

    memcpy(dictVal, val, len);
    tasvir_log_write(dictVal, len);
    return dictVal;
}


static int compareCallback(__unused void *privdata, const void *key1, const void *key2) {
    int l1, l2;
    l1 = strlen((const char *)key1);
    l2 = strlen((const char *)key2);
    if (l1 != l2)
        return 0;
    return memcmp(key1, key2, l1) == 0;
}

dictType AllocDictType = {hashCallback,     NULL,           NULL, compareCallback, keyDestructor, valDestructor,
                          entryConstructor, entryDestructor, entryModed};

dictWrapper *initDictWrapper(void *space, size_t len, void *entrySpace, size_t entrySize, void *keySpace, size_t keyLen,
                             size_t keySize, void *valSpace, size_t valLen, size_t valSize) {
    dictWrapper *wrapper = (dictWrapper *)space;
    wrapper->entryAllocator = init_allocator(entrySpace, entrySize, sizeof(dictEntry));
    wrapper->keyAllocator = init_allocator(keySpace, keySize, keyLen);
    wrapper->valAllocator = init_allocator(valSpace, valSize, valLen);
    void *dspace = (void *)(((intptr_t)space) + sizeof(dictWrapper));
    wrapper->d = dictCreate(&AllocDictType, wrapper, dspace, len - sizeof(dictWrapper));
    return wrapper;
}
