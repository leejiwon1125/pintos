#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

#define SECTOR_NUM_IN_ONE_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_disk;
struct bitmap *swap_disk_bitmap; // false -> there is space in swap disk.

void swap_disk_init(void);
void swap_in(void *, size_t);
size_t swap_out(void *);

#endif