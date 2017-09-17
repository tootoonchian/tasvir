#include "alloc.h"
Allocator *init_allocator(void *space, size_t len, size_t obj_len) {
    Allocator *alloc = (Allocator*)space;
    size_t remaining = 0;
    size_t obj_size = obj_len > sizeof(FreeNode) ? obj_len : sizeof(FreeNode);

    if (len < sizeof(Allocator) + obj_size) {
        return NULL;
    }
    remaining = len - sizeof(Allocator);
    alloc->used = 0;
    alloc->alloc_size = obj_size;
    alloc->head = (FreeNode*)((uintptr_t)space + sizeof(Allocator));
    alloc->head->size = remaining; 
    alloc->head->next = NULL;
    return alloc;
}

void *alloc_allocator(Allocator *allocator) {
    if (allocator->head) {
        uintptr_t head = (uintptr_t)allocator->head;
        if (allocator->head->size >= 2 * allocator->alloc_size) {
            size_t new_tail_size = allocator->head->size - allocator->alloc_size;
            allocator->head = (FreeNode*)(head + allocator->alloc_size);
            allocator->head->next = NULL;
            allocator->head->size = new_tail_size;
        } else {
            allocator->head = allocator->head->next;
        }
        return (void*)head;
    }
    return NULL;
}

void free_allocator(Allocator *allocator, void *region) {
    FreeNode *node = (FreeNode*)region;
    node->next = allocator->head;
    node->size = allocator->alloc_size;
    allocator->head = node;
}
