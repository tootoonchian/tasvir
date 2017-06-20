#include <stdint.h>
#include <stddef.h>
#pragma once

typedef struct FreeNode {
    struct FreeNode *next;
    size_t size;
} FreeNode;

typedef struct Allocator {
    FreeNode *head; 
    size_t used;
    size_t alloc_size;
} Allocator;

Allocator *init_allocator(void *space, size_t len, size_t obj_len);
void *alloc_allocator(Allocator *allocator); 
void free_allocator(Allocator *allocator, void *region);
