#include <spt.h>

unsigned sup_page_table_hash_function (const struct hash_elem * e, void * aux)
{
    struct sup_page_table_entry * spt_entry = hash_entry (e, struct sup_page_table_entry, spt_entry_elem);
    unsigned hash = hash_int((int)(spt_entry -> VA_for_page));
    return hash;
}

bool sup_page_table_less_func (const struct hash_elem * a, const struct hash_elem * b, void * aux)
{
    struct sup_page_table_entry * spt_entry_a = hash_entry (a, struct sup_page_table_entry, spt_entry_elem);
    struct sup_page_table_entry * spt_entry_b = hash_entry (b, struct sup_page_table_entry, spt_entry_elem);
    return (spt_entry_a -> VA_for_page) < (spt_entry_b -> VA_for_page);
}

void sup_page_table_destruct_func (struct hash_elem * e, void * aux)
{
    // need to free memory that used for buckets' element's element
    // type of...
    // buckets: array / buckets' element: struct list / buckets' element's element: struct sup_page_table_entry
    struct sup_page_table_entry * spt_entry = hash_entry (e, struct sup_page_table_entry, spt_entry_elem);
    hash_delete(&(thread_current() -> sup_page_table), e);
    free(spt_entry);
}