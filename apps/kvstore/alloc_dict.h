#include "alloc.h"
#include "dict.h"
#ifndef __ALLOC_DICT__
#define __ALLOC_DICT__
typedef struct dictWrapper {
    Allocator *entryAllocator;
    Allocator *keyAllocator;
    Allocator *valAllocator;
    dict *d;
} dictWrapper;
dictWrapper *initDictWrapper(void *space, size_t len, void *entrySpace, size_t entrySize, void *keySpace, size_t keyLen,
                             size_t keySize, void *valSpace, size_t valLen, size_t valSize);
char *allocKey(dictWrapper *wrapper, const char *key);
void *allocVal(dictWrapper *wrapper, void *val, size_t len);
#endif
