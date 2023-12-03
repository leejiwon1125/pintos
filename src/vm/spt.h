#ifndef VM_SPT_H
#define VM_SPT_H

#include <hash.h>
#include "filesys/file.h"
#include "threads/thread.h"
#include "vm/swap.h"

unsigned sup_page_table_hash_function(const struct hash_elem *, void *);
bool sup_page_table_less_func(const struct hash_elem *, const struct hash_elem *, void *);
void sup_page_table_destruct_func(struct hash_elem *, void *);
void free_sup_page_table(struct hash *);

enum current_location_for_page
{
    InMemory,
    InFile,
    InSwapDisk
};

struct sup_page_table_entry
{
    struct file *file;
    off_t ofs;
    void *spte_VA_for_page;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;

    enum current_location_for_page current_page_location;
    bool go_to_swap_disk_when_evict;

    off_t frame_idx_in_swap_disk;

    struct hash_elem elem;
};

#endif /* vm/spt.h */