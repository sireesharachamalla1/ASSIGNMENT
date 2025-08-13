#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define POOL_SIZE (100 * 1024)  // 100 KB pool
#define ALIGNMENT 8  // 8-byte alignment

typedef struct Block {
    size_t size;        // Size of user data
    int free;           // 1 if free, 0 if allocated
    struct Block *next; // Next block in pool
    struct Block *prev; // Previous block in pool
} Block;

#define BLOCK_HEADER_SIZE sizeof(Block)

static union {
    uint8_t pool[POOL_SIZE];
    long long align;  // Force alignment
} memory_pool;

static Block *pool_head = NULL;
static Block *free_list = NULL;
static int pool_initialized = 0;

static uint8_t* pool_base(void) { return memory_pool.pool; }
static size_t pool_size(void) { return POOL_SIZE; }

// Align size to ALIGNMENT boundary
static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static void* block_to_data(Block *b) {
    return (void *)((uint8_t *)b + BLOCK_HEADER_SIZE);
}

static Block* data_to_block(void *ptr) {
    return (Block *)((uint8_t *)ptr - BLOCK_HEADER_SIZE);
}

static int block_in_pool(Block *b) {
    uint8_t *base = pool_base();
    uint8_t *end = base + pool_size();
    uint8_t *p = (uint8_t *)b;
    return (p >= base && p + BLOCK_HEADER_SIZE <= end);
}

static void init_pool(void) {
    if (pool_initialized) return;
    pool_head = (Block *)pool_base();
    pool_head->size = pool_size() - BLOCK_HEADER_SIZE;
    pool_head->free = 1;
    pool_head->next = NULL;
    pool_head->prev = NULL;
    free_list = pool_head;
    pool_initialized = 1;
}

static void free_list_insert(Block *b)
{
         printf("status of dealloacting pointer in free list block after dealloc%d\n",b->free);
    b->free = 1;
    b->next = free_list;
    if (free_list) {
        free_list->prev = b;
    }
    b->prev = NULL;
    free_list = b;
}

static void free_list_remove(Block *b) {
    //printf("status of dealloacting pointer in free list block after dealloc%d\n",b->free);
    if (b->prev) {
        b->prev->next = b->next;
    } else {
        free_list = b->next;
    }
    if (b->next) {
        b->next->prev = b->prev;
    }
    b->prev = NULL;
    b->next = NULL;
}

static Block* split_block(Block *b, size_t size) {
    size_t aligned_size = align_size(size);
    size_t remaining_size = b->size - aligned_size;

    if (remaining_size >= BLOCK_HEADER_SIZE + ALIGNMENT) {
        uint8_t *data_start = (uint8_t *)block_to_data(b);
        Block *rem = (Block *)(data_start + aligned_size);

        if (!block_in_pool(rem)) return NULL;

        rem->size = remaining_size - BLOCK_HEADER_SIZE;
        rem->free = 1;
        rem->next = b->next;
        rem->prev = b;

        if (b->next) {
            b->next->prev = rem;
        }

        b->size = aligned_size;
        b->next = rem;
        return rem;
    }
    return NULL;
}

static void coalesce_blocks() {
    Block *cur = pool_head;
    while (cur && cur->next) {
        if (cur->free && cur->next->free) {
            // Check if blocks are adjacent
            uint8_t *cur_end = (uint8_t *)cur + BLOCK_HEADER_SIZE + cur->size;
            uint8_t *next_start = (uint8_t *)cur->next;

            if (cur_end == next_start) {
                // Merge blocks
                cur->size += BLOCK_HEADER_SIZE + cur->next->size;
                Block *next_block = cur->next;
                cur->next = next_block->next;
                if (cur->next) {
                    cur->next->prev = cur;
                }
                // Continue with the same block to check for more merges
                continue;
            }
        }
        cur = cur->next;
    }
}

void* allocate(int size) {
    if (size <= 0 || (size_t)size > pool_size() - BLOCK_HEADER_SIZE) return NULL;
    if (!pool_initialized) init_pool();

    size_t aligned_size = align_size((size_t)size);
    Block *best = NULL;

    // First-fit allocation in free list
    Block *current = free_list;
    while (current) {
        if (current->size >= aligned_size) {
            best = current;
            break;
        }
        current = current->next;
    }

    if (!best) {
        coalesce_blocks();

        // Rebuild free list after coalescing
        free_list = NULL;
        Block *cur = pool_head;
        while (cur) {
            if (cur->free) {
                free_list_insert(cur);
            }
            cur = cur->next;
        }

        // Try again after coalescing
        current = free_list;
        while (current) {
            if (current->size >= aligned_size) {
                best = current;
                break;
            }
            current = current->next;
        }
        if (!best) return NULL;
    }

    // Remove from free list
    free_list_remove(best);

    // Split block if possible
    Block *rem = split_block(best, aligned_size);
    if (rem) {
        free_list_insert(rem);
    }

    best->free = 0;
    return block_to_data(best);
}

void deallocate(void *ptr) {
    printf("ptr in deallocate: %p\n", ptr);

    if (!ptr) {
        printf("Pointer is NULL.\n");
        return;
    }

    Block *b = data_to_block(ptr);

    if (!block_in_pool(b)) {
        printf("Pointer is not within pool.\n");
        return;
    }

    if (b->free) {
        printf("Block is already free.\n");
        return;
    }

    // Check that ptr exactly matches block data pointer
    if (ptr != block_to_data(b)) {
        printf("Pointer does not point to start of a block.\n");
        return;
    }

    printf("Deallocating block at %p (size: %zu)\n", (void*)b, b->size);

    // Mark as free
    printf("status of dealloacting pointer in dealloc block before dealloc%d\n",b->free);
    b->free = 1;
    printf("status of dealloacting pointer in dealloc block after dealloc%d\n",b->free);
    // Coalesce adjacent free blocks
    coalesce_blocks();

    // Add to free list
    free_list_insert(b);

    printf("Block deallocated successfully.\n");
}

void print_pool() {
    Block *cur = pool_head;
    printf("\n=== Pool State ===\n");
    int block_num = 0;

    while (cur) {
        printf("Block %d at %p - size: %zu bytes, status:%d %s\n",
               block_num++, (void*)cur, cur->size, cur->free,
               cur->free ? "FREE" : "ALLOCATED");
        cur = cur->next;
    }

    printf("\n=== Free List ===\n");
    cur = free_list;
    block_num = 0;
    while (cur) {
        printf("Free block %d at %p - size: %zu bytes\n",
               block_num++, (void*)cur, cur->size);
        cur = cur->next;
    }
    printf("==================\n\n");
}

int main() {
    init_pool();

    printf("Memory Pool Allocator\n");
    printf("Pool size: %d KB\n", POOL_SIZE / 1024);

    while(1) {
        int choice;
        printf("Select option:\n");
        printf("1. Allocate\n");
        printf("2. Deallocate\n");
        printf("3. Print Pool\n");
        printf("4. Exit\n");
        printf("Choice: ");

        if (scanf("%d", &choice) != 1) {
            int c;
            while((c = getchar()) != '\n' && c != EOF);
            printf("Invalid input.\n");
            continue;
        }

        switch(choice) {
            case 1: {
                int size;
                printf("Enter allocation size (bytes): ");
                if (scanf("%d", &size) != 1 || size <= 0) {
                    printf("Invalid size.\n");
                    break;
                }

                void *p = allocate(size);
                if (p) {
                    printf("Allocated %d bytes at address %p\n", size, p);
                } else {
                    printf("Allocation failed. Not enough memory.\n");
                }
                break;
            }
            case 2: {
                printf("Enter pointer address to deallocate (e.g., 0x1234abcd): ");
                void *p = NULL;
                if (scanf("%p", &p) != 1) {
                    printf("Invalid pointer format.\n");
                    break;
                }

                printf("Attempting to deallocate pointer: %p\n", p);
                deallocate(p);
                break;
            }
            case 3:
                print_pool();
                break;
            case 4:
                printf("Exiting.\n");
                return 0;
            default:
                printf("Invalid choice.\n");
        }

        // Clear input buffer
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }

    return 0;
}
~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                               #include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define POOL_SIZE (100 * 1024)  // 100 KB pool
#define ALIGNMENT 8  // 8-byte alignment

typedef struct Block {
    size_t size;        // Size of user data
    int free;           // 1 if free, 0 if allocated
    struct Block *next; // Next block in pool
    struct Block *prev; // Previous block in pool
} Block;

#define BLOCK_HEADER_SIZE sizeof(Block)

static union {
    uint8_t pool[POOL_SIZE];
    long long align;  // Force alignment
} memory_pool;

static Block *pool_head = NULL;
static Block *free_list = NULL;
static int pool_initialized = 0;

static uint8_t* pool_base(void) { return memory_pool.pool; }
static size_t pool_size(void) { return POOL_SIZE; }

// Align size to ALIGNMENT boundary
static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static void* block_to_data(Block *b) {
    return (void *)((uint8_t *)b + BLOCK_HEADER_SIZE);
}

static Block* data_to_block(void *ptr) {
    return (Block *)((uint8_t *)ptr - BLOCK_HEADER_SIZE);
}

static int block_in_pool(Block *b) {
    uint8_t *base = pool_base();
    uint8_t *end = base + pool_size();
    uint8_t *p = (uint8_t *)b;
    return (p >= base && p + BLOCK_HEADER_SIZE <= end);
}

static void init_pool(void) {
    if (pool_initialized) return;
    pool_head = (Block *)pool_base();
    pool_head->size = pool_size() - BLOCK_HEADER_SIZE;
    pool_head->free = 1;
    pool_head->next = NULL;
    pool_head->prev = NULL;
    free_list = pool_head;
    pool_initialized = 1;
}

static void free_list_insert(Block *b)
{
         printf("status of dealloacting pointer in free list block after dealloc%d\n",b->free);
    b->free = 1;
    b->next = free_list;
    if (free_list) {
        free_list->prev = b;
    }
    b->prev = NULL;
    free_list = b;
}

static void free_list_remove(Block *b) {
    //printf("status of dealloacting pointer in free list block after dealloc%d\n",b->free);
    if (b->prev) {
        b->prev->next = b->next;
    } else {
        free_list = b->next;
    }
    if (b->next) {
        b->next->prev = b->prev;
    }
    b->prev = NULL;
    b->next = NULL;
}

static Block* split_block(Block *b, size_t size) {
    size_t aligned_size = align_size(size);
    size_t remaining_size = b->size - aligned_size;

    if (remaining_size >= BLOCK_HEADER_SIZE + ALIGNMENT) {
        uint8_t *data_start = (uint8_t *)block_to_data(b);
        Block *rem = (Block *)(data_start + aligned_size);

        if (!block_in_pool(rem)) return NULL;

        rem->size = remaining_size - BLOCK_HEADER_SIZE;
        rem->free = 1;
        rem->next = b->next;
        rem->prev = b;

        if (b->next) {
            b->next->prev = rem;
        }

        b->size = aligned_size;
        b->next = rem;
        return rem;
    }
    return NULL;
}

static void coalesce_blocks() {
    Block *cur = pool_head;
    while (cur && cur->next) {
        if (cur->free && cur->next->free) {
            // Check if blocks are adjacent
            uint8_t *cur_end = (uint8_t *)cur + BLOCK_HEADER_SIZE + cur->size;
            uint8_t *next_start = (uint8_t *)cur->next;

            if (cur_end == next_start) {
                // Merge blocks
                cur->size += BLOCK_HEADER_SIZE + cur->next->size;
                Block *next_block = cur->next;
                cur->next = next_block->next;
                if (cur->next) {
                    cur->next->prev = cur;
                }
                // Continue with the same block to check for more merges
                continue;
            }
        }
        cur = cur->next;
    }
}

void* allocate(int size) {
    if (size <= 0 || (size_t)size > pool_size() - BLOCK_HEADER_SIZE) return NULL;
    if (!pool_initialized) init_pool();

    size_t aligned_size = align_size((size_t)size);
    Block *best = NULL;

    // First-fit allocation in free list
    Block *current = free_list;
    while (current) {
        if (current->size >= aligned_size) {
            best = current;
            break;
        }
        current = current->next;
    }

    if (!best) {
        coalesce_blocks();

        // Rebuild free list after coalescing
        free_list = NULL;
        Block *cur = pool_head;
        while (cur) {
            if (cur->free) {
                free_list_insert(cur);
            }
            cur = cur->next;
        }

        // Try again after coalescing
        current = free_list;
        while (current) {
            if (current->size >= aligned_size) {
                best = current;
                break;
            }
            current = current->next;
        }
        if (!best) return NULL;
    }

    // Remove from free list
    free_list_remove(best);

    // Split block if possible
    Block *rem = split_block(best, aligned_size);
    if (rem) {
        free_list_insert(rem);
    }

    best->free = 0;
    return block_to_data(best);
}

void deallocate(void *ptr) {
    printf("ptr in deallocate: %p\n", ptr);

    if (!ptr) {
        printf("Pointer is NULL.\n");
        return;
    }

    Block *b = data_to_block(ptr);

    if (!block_in_pool(b)) {
        printf("Pointer is not within pool.\n");
        return;
    }

    if (b->free) {
        printf("Block is already free.\n");
        return;
    }

    // Check that ptr exactly matches block data pointer
    if (ptr != block_to_data(b)) {
        printf("Pointer does not point to start of a block.\n");
        return;
    }

    printf("Deallocating block at %p (size: %zu)\n", (void*)b, b->size);

    // Mark as free
    printf("status of dealloacting pointer in dealloc block before dealloc%d\n",b->free);
    b->free = 1;
    printf("status of dealloacting pointer in dealloc block after dealloc%d\n",b->free);
    // Coalesce adjacent free blocks
    coalesce_blocks();

    // Add to free list
    free_list_insert(b);

    printf("Block deallocated successfully.\n");
}

void print_pool() {
    Block *cur = pool_head;
    printf("\n=== Pool State ===\n");
    int block_num = 0;

    while (cur) {
        printf("Block %d at %p - size: %zu bytes, status:%d %s\n",
               block_num++, (void*)cur, cur->size, cur->free,
               cur->free ? "FREE" : "ALLOCATED");
        cur = cur->next;
    }

    printf("\n=== Free List ===\n");
    cur = free_list;
    block_num = 0;
    while (cur) {
        printf("Free block %d at %p - size: %zu bytes\n",
               block_num++, (void*)cur, cur->size);
        cur = cur->next;
    }
    printf("==================\n\n");
}

int main() {
    init_pool();

    printf("Memory Pool Allocator\n");
    printf("Pool size: %d KB\n", POOL_SIZE / 1024);

    while(1) {
        int choice;
        printf("Select option:\n");
        printf("1. Allocate\n");
        printf("2. Deallocate\n");
        printf("3. Print Pool\n");
        printf("4. Exit\n");
        printf("Choice: ");

        if (scanf("%d", &choice) != 1) {
            int c;
            while((c = getchar()) != '\n' && c != EOF);
            printf("Invalid input.\n");
            continue;
        }

        switch(choice) {
            case 1: {
                int size;
                printf("Enter allocation size (bytes): ");
                if (scanf("%d", &size) != 1 || size <= 0) {
                    printf("Invalid size.\n");
                    break;
                }

                void *p = allocate(size);
                if (p) {
                    printf("Allocated %d bytes at address %p\n", size, p);
                } else {
                    printf("Allocation failed. Not enough memory.\n");
                }
                break;
            }
            case 2: {
                printf("Enter pointer address to deallocate (e.g., 0x1234abcd): ");
                void *p = NULL;
                if (scanf("%p", &p) != 1) {
                    printf("Invalid pointer format.\n");
                    break;
                }

                printf("Attempting to deallocate pointer: %p\n", p);
                deallocate(p);
                break;
            }
            case 3:
                print_pool();
                break;
            case 4:
                printf("Exiting.\n");
                return 0;
            default:
                printf("Invalid choice.\n");
        }

        // Clear input buffer
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }

    return 0;
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ~                                               