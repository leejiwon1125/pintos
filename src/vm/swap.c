#include "vm/swap.h"

void swap_disk_init(void)
{
    swap_disk = block_get_role(BLOCK_SWAP);
    uint32_t num_of_sector_in_swap_disk = block_size(swap_disk);
    // cause we handle swap disk as page size chunk. 
    swap_disk_bitmap = bitmap_create( num_of_sector_in_swap_disk / SECTOR_NUM_IN_ONE_PAGE );
    bitmap_set_all(swap_disk_bitmap, false);
}

void swap_in(void * kernel_VA_for_frame, size_t frame_idx_in_swap_disk)
{
    size_t i;

    lock_acquire(&swap_disk_bitmap_lock);
    // mark swap_disk_bitmap as "false" becuase page is going out. from swap disk to memory
    bitmap_flip(swap_disk_bitmap, frame_idx_in_swap_disk);
    lock_release(&swap_disk_bitmap_lock);

    for(i = 0; i < SECTOR_NUM_IN_ONE_PAGE; i++)
    {
        block_read (
            swap_disk, 
            frame_idx_in_swap_disk * SECTOR_NUM_IN_ONE_PAGE + i, 
            kernel_VA_for_frame + i * BLOCK_SECTOR_SIZE
        );
    }
}

size_t swap_out(void * kernel_VA_for_frame)
{
    size_t i;
    size_t frame_idx_in_swap_disk;

    lock_acquire(&swap_disk_bitmap_lock);
    // mark swap_disk_bitmap as "true" because page is coming to swap disk (from memory)
    frame_idx_in_swap_disk = bitmap_scan_and_flip(swap_disk_bitmap, 0, 1, false);
    lock_release(&swap_disk_bitmap_lock);

    // no space in swap disk -> kernel panic (dye)
    ASSERT (frame_idx_in_swap_disk != BITMAP_ERROR);
    
    for(i = 0; i < SECTOR_NUM_IN_ONE_PAGE; i++)
    {
        block_write (
            swap_disk, 
            frame_idx_in_swap_disk * SECTOR_NUM_IN_ONE_PAGE + i, 
            kernel_VA_for_frame + i * BLOCK_SECTOR_SIZE
        );
    }

    return frame_idx_in_swap_disk;

}

void 
swap_disk_free (size_t bit_idx)
{
    ASSERT(bitmap_scan(swap_disk_bitmap,bit_idx,1,true) == bit_idx);
    lock_acquire(&swap_disk_bitmap_lock);
    bitmap_flip (swap_disk_bitmap, bit_idx);
    lock_release(&swap_disk_bitmap_lock);
}