////////////////////////////////////////////////////////////////////////////////
// Main File:        p3Heap.c
// This File:        p3Heap.c
// Other Files:      N/A
// Semester:         CS 354 Lecture 02 Spring 2023
// Instructor:       deppeler
// 
// Author:           Shrey Ramesh
// Email:            snramesh@wisc.edu
// CS Login:         ramesh
//
/////////////////////////// OTHER SOURCES OF HELP //////////////////////////////
//
// Persons:          N/A
//
// Online sources:   N/A
//////////////////////////// 80 columns wide ///////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2020-2023 Deb Deppeler based on work by Jim Skrentny
// Posting or sharing this file is prohibited, including any changes/additions.
// Used by permission SPRING 2023, CS354-deppeler
//
///////////////////////////////////////////////////////////////////////////////

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include "p3Heap.h"
 
/*
 * This structure serves as the header for each allocated and free block.
 * It also serves as the footer for each free block but only containing size.
 */
typedef struct blockHeader {           

    int size_status;

    /*
     * Size of the block is always a multiple of 8.
     * Size is stored in all block headers and in free block footers.
     *
     * Status is stored only in headers using the two least significant bits.
     *   Bit0 => least significant bit, last bit
     *   Bit0 == 0 => free block
     *   Bit0 == 1 => allocated block
     *
     *   Bit1 => second last bit 
     *   Bit1 == 0 => previous block is free
     *   Bit1 == 1 => previous block is allocated
     * 
     * Start Heap: 
     *  The blockHeader for the first block of the heap is after skip 4 bytes.
     *  This ensures alignment requirements can be met.
     * 
     * End Mark: 
     *  The end of the available memory is indicated using a size_status of 1.
     * 
     * Examples:
     * 
     * 1. Allocated block of size 24 bytes:
     *    Allocated Block Header:
     *      If the previous block is free      p-bit=0 size_status would be 25
     *      If the previous block is allocated p-bit=1 size_status would be 27
     * 
     * 2. Free block of size 24 bytes:
     *    Free Block Header:
     *      If the previous block is free      p-bit=0 size_status would be 24
     *      If the previous block is allocated p-bit=1 size_status would be 26
     *    Free Block Footer:
     *      size_status should be 24
     */
} blockHeader;         

/* Global variable - DO NOT CHANGE NAME or TYPE. 
 * It must point to the first block in the heap and is set by init_heap()
 * i.e., the block at the lowest address.
 */
blockHeader *heap_start = NULL;     

/* Size of heap allocation padded to round to nearest page size.
 */
int alloc_size;

/*
 * Additional global variables may be added as needed below
 * TODO: add global variables needed by your function
 */

blockHeader *heap_end = NULL;

/* This function finds the end of the heap and stores it in a global varaible to used
 * in the balloc, bfree, and coalesce functions
 *
 * Pre-conditions: The heap should be initialized before this function is called
 *
 * Returns a blockHeader* to the start of the heap_end block which should have a 
 * which should have a size_status of 1
 */
 blockHeader* find_heap_end() {
    blockHeader* heap_end = heap_start;
    while (heap_end->size_status != 1) { // Finding address of the end of the heap
        heap_end = (void*) heap_end + ((heap_end->size_status >> 2) << 2);
    }

    return heap_end;
}

/* 
 * Function for allocating 'size' bytes of heap memory.
 * Argument size: requested size for the payload
 * Returns address of allocated block (payload) on success.
 * Returns NULL on failure.
 *
 * This function must:
 * - Check size - Return NULL if size < 1 
 * - Determine block size rounding up to a multiple of 8 
 *   and possibly adding padding as a result.
 *
 * - Use BEST-FIT PLACEMENT POLICY to chose a free block
 *
 * - If the BEST-FIT block that is found is exact size match
 *   - 1. Update all heap blocks as needed for any affected blocks
 *   - 2. Return the address of the allocated block payload
 *
 * - If the BEST-FIT block that is found is large enough to split 
 *   - 1. SPLIT the free block into two valid heap blocks:
 *         1. an allocated block
 *         2. a free block
 *         NOTE: both blocks must meet heap block requirements 
 *       - Update all heap block header(s) and footer(s) 
 *              as needed for any affected blocks.
 *   - 2. Return the address of the allocated block payload
 *
 *   Return if NULL unable to find and allocate block for required size
 *
 * Note: payload address that is returned is NOT the address of the
 *       block header.  It is the address of the start of the 
 *       available memory for the requesterr.
 *
 * Tips: Be careful with pointer arithmetic and scale factors.
 */
void* balloc(int size) {     
    //TODO: Your code goes in here.
    // disp_heap();

    // Setting heap_end if it has not been set yet
    if(heap_end == NULL) {
        heap_end = find_heap_end();
    }

    if (size < 1 || heap_start == NULL) {
        return NULL;
    }

    int header_size = sizeof(blockHeader);
    int padding_size = ((header_size + size) % 8 != 0) ? (8 - ((size + header_size) % 8)) : 0;
    int block_size = size + header_size + padding_size;
    // printf("Allocating new block w/ size: %i\tblock_size: %i\n", size, block_size);
    // printf("size: %i, header: %i, padding: %i, block: %i\n", size, header_size, padding_size, block_size);

    // Looping through implicit free list
    blockHeader* chosen_block = NULL;
    blockHeader* curr_block = heap_start;
    int size_status = heap_start->size_status;
    // int curr_block_status = 3 & size_status;
    // int curr_block_size = (size_status >> 2) << 2;

    while (size_status != 1) {
        // printf("%i\n", size_status);
        int curr_block_status = 3 & size_status;
        int curr_block_size = (size_status >> 2) << 2;
        // printf("%p %i %i\n", curr_block, curr_block_status, curr_block_size);

        // Checking if a-bit is 1 - ALLOCATED
        if(curr_block_status % 2 == 1) {
            curr_block = (void*) curr_block + curr_block_size;
            size_status = curr_block->size_status;
            continue;
        }

        if(chosen_block == NULL && curr_block_size >= block_size) {
            chosen_block = curr_block;

            if(curr_block_size == block_size) {
                break;
            }
        } else {
             if(curr_block_size == block_size) {
                chosen_block = curr_block;
                break;
             } else if (curr_block_size > block_size && curr_block_size < ((chosen_block->size_status >> 2) << 2)) {
                chosen_block = curr_block;
             }
        }

        curr_block = (void*) curr_block + curr_block_size; 
        size_status = curr_block->size_status;
        // printf("here...%p", curr_block); 
    }
    
    if(chosen_block == NULL) { // No space for this block
        return NULL;
    }

    
    // Allocating block
    chosen_block->size_status += 1; // Setting a-bit to 1 
    int full_chosen_block_size = (chosen_block->size_status >> 2) << 2;
    int full_chosen_block_status = 3 & chosen_block->size_status;
    if(full_chosen_block_size > block_size) { // Checking for splitting
        int new_free_block_size = full_chosen_block_size - block_size;
        int new_chosen_block_size = full_chosen_block_size - new_free_block_size;
        chosen_block->size_status = new_chosen_block_size + full_chosen_block_status;

        blockHeader* free_block_header = (void*) chosen_block + new_chosen_block_size;
        free_block_header->size_status = new_free_block_size + 2; // Prev block alloc'd and this is a free block so "10"

        // printf("%p %p", chosen_block, free_block_header);

        blockHeader* free_block_footer = (void*) free_block_header + new_free_block_size - sizeof(blockHeader);
        // printf("footer: %p\n", free_block_footer);
        free_block_footer->size_status = new_free_block_size;

        
    } else {
        blockHeader* next_block = (void*) chosen_block + full_chosen_block_size;

        if(next_block != heap_end) {
            next_block->size_status += 2;
        }
    }

    // printf("chosen block: %p, size: %i, status: %i\n", chosen_block, ((chosen_block->size_status >> 2) << 2), (3 & chosen_block->size_status));

    // printf("heap end: %p w/ size_status: %i\n", heap_end, heap_end->size_status);
    // disp_heap();

    return (void*) chosen_block + sizeof(blockHeader);
} 
 
/* 
 * Function for freeing up a previously allocated block.
 * Argument ptr: address of the block to be freed up.
 * Returns 0 on success.
 * Returns -1 on failure.
 * This function should:
 * - Return -1 if ptr is NULL.
 * - Return -1 if ptr is not a multiple of 8.
 * - Return -1 if ptr is outside of the heap space.
 * - Return -1 if ptr block is already freed.
 * - Update header(s) and footer as needed.
 */                    
int bfree(void *ptr) {    
    //TODO: Your code goes in here.
    // Return -1 if ptr is NULL.
    if (ptr == NULL) {
        return -1;
    }

    // Return -1 if ptr is not a multiple of 8.
    blockHeader* block_header = ptr - sizeof(blockHeader);
    int block_status = 3 & block_header->size_status;
    int block_size = (block_header->size_status >> 2) << 2;
    if (block_size % 8 != 0) {
        return -1;
    }

    // Return -1 if ptr is outside of the heap space.
    if(heap_end == NULL) {
        heap_end = find_heap_end();
    }
    // printf("heap end: %p\n", heap_end);
    if (ptr < (void*) heap_start || ptr > (void*) heap_end) {
        return -1;
    }

    // Return -1 if ptr block is already freed.
    if (block_status % 2 == 0) {
        return -1;
    }

    // Freeing block

    // printf("Freeing: %p w/ size: %i\n", block_header, block_size);
    // Setting block a-bit to 0
    block_header->size_status -= 1;

    // Creating footer
    blockHeader* free_block_footer = (void*) block_header + block_size - sizeof(blockHeader);
    free_block_footer->size_status = block_size;

    // Setting next block p-bit to 0 unless it is heap_end
    blockHeader* next_block = (void *) block_header + block_size;
    if (next_block != heap_end) {
        next_block->size_status -= 2;
    }

    // printf("heap end: %p w/ size_status: %i\n", heap_end, heap_end->size_status);
    // Sdisp_heap();

    return 0;
} 

/*
 * Function for traversing heap block list and coalescing all adjacent 
 * free blocks.
 *
 * This function is used for user-called coalescing.
 * Updated header size_status and footer size_status as needed.
 */
int coalesce() {
    // disp_heap();
    //TODO: Your code goes in here.
    if (heap_end == NULL) {
        heap_end = find_heap_end();
    }

    blockHeader* curr_block = heap_start;
    int number_coalesced = 0;

    // Looping through heap to look for adjacent free blocks
    while(curr_block != heap_end) {
        int curr_block_status = 3 & curr_block->size_status;
        int curr_block_size = (curr_block->size_status >> 2) << 2;
        // printf("curr_block: %p size: %i status: %i\n", curr_block, curr_block_size, curr_block_status);

        if (curr_block_status % 2 != 0) { // Can't coalesce a alloc'd block
            curr_block = (void*) curr_block + curr_block_size;
            continue;
        } else {
            blockHeader* next_block = (void*) curr_block + curr_block_size;

            if(next_block == heap_end) { // Can't coalese with the heap_end block
                curr_block = (void*) curr_block + curr_block_size;
                continue; 
            }

            int next_block_status = 3 & next_block->size_status;
            int next_block_size = (next_block->size_status >> 2) << 2;

            // printf("next_block: %p size: %i status: %i\n", next_block, next_block_size, next_block_status);

            if (next_block_status % 2 != 0) { // Can't coalesce if the next block is an alloc'd block
                curr_block = (void*) curr_block + curr_block_size;
                continue;
            } else {
                number_coalesced += 1;

                // Updating size of free_block_header
                int new_free_block_size = curr_block_size + next_block_size;
                int new_free_block_status = curr_block_status;
                curr_block->size_status = new_free_block_size + new_free_block_status;

                // Updating the free_block_footer
                blockHeader* new_free_block_footer = (void*) curr_block + new_free_block_size - sizeof(blockHeader);
                new_free_block_footer->size_status = new_free_block_size;

                // printf("new_block: %p size: %i status: %i\n", curr_block, new_free_block_size, new_free_block_status);
            }
        }  
    }

    // disp_heap();
    
	return number_coalesced;
}
 
/* 
 * Function used to initialize the memory allocator.
 * Intended to be called ONLY once by a program.
 * Argument sizeOfRegion: the size of the heap space to be allocated.
 * Returns 0 on success.
 * Returns -1 on failure.
 */                    
int init_heap(int sizeOfRegion) {    
 
    static int allocated_once = 0; //prevent multiple myInit calls
 
    int   pagesize; // page size
    int   padsize;  // size of padding when heap size not a multiple of page size
    void* mmap_ptr; // pointer to memory mapped area
    int   fd;

    blockHeader* end_mark;
  
    if (0 != allocated_once) {
        fprintf(stderr, 
        "Error:mem.c: InitHeap has allocated space during a previous call\n");
        return -1;
    }

    if (sizeOfRegion <= 0) {
        fprintf(stderr, "Error:mem.c: Requested block size is not positive\n");
        return -1;
    }

    // Get the pagesize from O.S. 
    pagesize = getpagesize();

    // Calculate padsize as the padding required to round up sizeOfRegion 
    // to a multiple of pagesize
    padsize = sizeOfRegion % pagesize;
    padsize = (pagesize - padsize) % pagesize;

    alloc_size = sizeOfRegion + padsize;

    // Using mmap to allocate memory
    fd = open("/dev/zero", O_RDWR);
    if (-1 == fd) {
        fprintf(stderr, "Error:mem.c: Cannot open /dev/zero\n");
        return -1;
    }
    mmap_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == mmap_ptr) {
        fprintf(stderr, "Error:mem.c: mmap cannot allocate space\n");
        allocated_once = 0;
        return -1;
    }
  
    allocated_once = 1;

    // for double word alignment and end mark
    alloc_size -= 8;

    // Initially there is only one big free block in the heap.
    // Skip first 4 bytes for double word alignment requirement.
    heap_start = (blockHeader*) mmap_ptr + 1;

    // Set the end mark
    end_mark = (blockHeader*)((void*)heap_start + alloc_size);
    end_mark->size_status = 1;

    // Set size in header
    heap_start->size_status = alloc_size;

    // Set p-bit as allocated in header
    // note a-bit left at 0 for free
    heap_start->size_status += 2;

    // Set the footer
    blockHeader *footer = (blockHeader*) ((void*)heap_start + alloc_size - 4);
    footer->size_status = alloc_size;
  
    return 0;
} 
                  
/* 
 * Function can be used for DEBUGGING to help you visualize your heap structure.
 * Traverses heap blocks and prints info about each block found.
 * 
 * Prints out a list of all the blocks including this information:
 * No.      : serial number of the block 
 * Status   : free/used (allocated)
 * Prev     : status of previous block free/used (allocated)
 * t_Begin  : address of the first byte in the block (where the header starts) 
 * t_End    : address of the last byte in the block 
 * t_Size   : size of the block as stored in the block header
 */                     
void disp_heap() {     
 
    int    counter;
    char   status[6];
    char   p_status[6];
    char * t_begin = NULL;
    char * t_end   = NULL;
    int    t_size;

    blockHeader *current = heap_start;
    counter = 1;

    int used_size =  0;
    int free_size =  0;
    int is_used   = -1;

    fprintf(stdout, 
	"*********************************** HEAP: Block List ****************************\n");
    fprintf(stdout, "No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
    fprintf(stdout, 
	"---------------------------------------------------------------------------------\n");
  
    while (current->size_status != 1) {
        t_begin = (char*)current;
        t_size = current->size_status;
    
        if (t_size & 1) {
            // LSB = 1 => used block
            strcpy(status, "alloc");
            is_used = 1;
            t_size = t_size - 1;
        } else {
            strcpy(status, "FREE ");
            is_used = 0;
        }

        if (t_size & 2) {
            strcpy(p_status, "alloc");
            t_size = t_size - 2;
        } else {
            strcpy(p_status, "FREE ");
        }

        if (is_used) 
            used_size += t_size;
        else 
            free_size += t_size;

        t_end = t_begin + t_size - 1;
    
        fprintf(stdout, "%d\t%s\t%s\t0x%08lx\t0x%08lx\t%4i\n", counter, status, 
        p_status, (unsigned long int)t_begin, (unsigned long int)t_end, t_size);
    
        current = (blockHeader*)((char*)current + t_size);
        counter = counter + 1;
    }

    fprintf(stdout, 
	"---------------------------------------------------------------------------------\n");
    fprintf(stdout, 
	"*********************************************************************************\n");
    fprintf(stdout, "Total used size = %4d\n", used_size);
    fprintf(stdout, "Total free size = %4d\n", free_size);
    fprintf(stdout, "Total size      = %4d\n", used_size + free_size);
    fprintf(stdout, 
	"*********************************************************************************\n");
    fflush(stdout);

    return;  
} 


int main(int argc, char *argv[]) {
    balloc(1);
}

// end p3Heap.c (Spring 2023)                                         


