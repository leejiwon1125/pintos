#include "vm/spt.h"

// helper function for hash_init
unsigned
sup_page_table_hash_function(const struct hash_elem *e, void *aux UNUSED)
{
    struct sup_page_table_entry *spt_entry = hash_entry(e, struct sup_page_table_entry, elem);
    unsigned hash = hash_int((int)(spt_entry->spte_VA_for_page));
    return hash;
}

// helper function for hash_init
bool sup_page_table_less_func(const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED)
{
    void *vaddr1 = hash_entry(e1, struct sup_page_table_entry, elem)->spte_VA_for_page;
    void *vaddr2 = hash_entry(e2, struct sup_page_table_entry, elem)->spte_VA_for_page;
    return vaddr1 < vaddr2; // ascending order
}

void sup_page_table_destruct_func(struct hash_elem *e, void *aux UNUSED)
{
    struct sup_page_table_entry *s_elem_to_free = hash_entry(e, struct sup_page_table_entry, elem);
    hash_delete(&thread_current()->sup_page_table, e);
    if (s_elem_to_free->current_page_location == InSwapDisk)
    {
        ASSERT(bitmap_scan(swap_disk_bitmap, s_elem_to_free->frame_idx_in_swap_disk, 1, true) == s_elem_to_free->frame_idx_in_swap_disk);
        bitmap_flip(swap_disk_bitmap, s_elem_to_free->frame_idx_in_swap_disk);
    }
    free(s_elem_to_free);
}

// free sup_page_table
void free_sup_page_table(struct hash *sup_page_table_to_free)
{
    hash_destroy(sup_page_table_to_free, sup_page_table_destruct_func);
}