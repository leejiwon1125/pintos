#ifndef VM_SPT_H
#define VM_SPT_H

#include <hash.h>
#include <file.h>
#include <thread.h>

enum current_location_for_page 
  {
    InMemory,
    InFile,
    InSwapDisk
  };

struct sup_page_table_entry
  {
    // for lazy loading
    struct file * file;
    off_t ofs;
    void * VA_for_page;
    uint32_t page_read_bytes;
    uint32_t page_zero_bytes;
    bool writable;

    // for evcition situation
    bool go_to_swap_disk_when_evict;
    enum current_location_for_page current_page_location;

    struct hash_elem spt_entry_elem;
  };

unsigned sup_page_table_hash_function (const struct hash_elem *, void *);
bool sup_page_table_less_func (const struct hash_elem *, const struct hash_elem *, void *);
void sup_page_table_destruct_func (struct hash_elem *, void *);
struct hash_elem * sup_page_table_find_hash_elem(struct hash *, void *);

#endif /* vm/spt.h */