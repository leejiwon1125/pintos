#include "vm/frame.h"
void *allocate_frame(enum palloc_flags flags);
static struct frame_table_entry *select_frame_to_evict(void);
static bool is_recently_accessed(struct frame_table_entry *entry);
static void handle_frame_eviction(struct frame_table_entry *frame_to_evict);
static void remove_and_free_frame(struct frame_table_entry *frame);

void frame_table_init(void)
{
    clock_ptr = NULL;
    list_init(&frame_table);
    lock_init(&frame_table_lock);
}

void *allocate_frame(enum palloc_flags flags)
{
    void *ret = palloc_get_page(flags);
    struct frame_table_entry *frame_to_evict = NULL;

    lock_acquire(&frame_table_lock);
    while (ret == NULL)
    {
        frame_to_evict = select_frame_to_evict();
        if (frame_to_evict != NULL)
        {
            handle_frame_eviction(frame_to_evict);
            ret = palloc_get_page(flags);
        }
        else
        {
            exit(-1);
        }
    }

    lock_release(&frame_table_lock);
    return ret;
}

static struct frame_table_entry *select_frame_to_evict()
{
    if (clock_ptr == NULL)
        clock_ptr = list_begin(&frame_table);
    while (clock_ptr != list_end(&frame_table))
    {
        struct frame_table_entry *ft_entry_tmp = list_entry(clock_ptr, struct frame_table_entry, fte_elem);
        if (ft_entry_tmp->able_to_evict && !is_recently_accessed(ft_entry_tmp))
        {
            return ft_entry_tmp;
        }
        clock_ptr = list_next(clock_ptr);
        if (clock_ptr == list_end(&frame_table))
            clock_ptr = list_begin(&frame_table);
    }
    return NULL;
}

static bool is_recently_accessed(struct frame_table_entry *entry)
{
    bool accessed = pagedir_is_accessed(entry->fte_thread->pagedir, entry->fte_VA_for_page);
    if (accessed)
    {
        pagedir_set_accessed(entry->fte_thread->pagedir, entry->fte_VA_for_page, false);
        return true;
    }
    return false;
}

static void handle_frame_eviction(struct frame_table_entry *frame_to_evict)
{
    if (frame_to_evict->fte_sup_page_table_entry->go_to_swap_disk_when_evict)
    {
        frame_to_evict->fte_sup_page_table_entry->frame_idx_in_swap_disk = swap_out(frame_to_evict->fte_kernel_VA_for_frame);
        frame_to_evict->fte_sup_page_table_entry->current_page_location = InSwapDisk;
    }
    else
    {
        if (pagedir_is_dirty(frame_to_evict->fte_thread->pagedir, frame_to_evict->fte_VA_for_page))
        {
            lock_acquire(&filesys_lock);
            file_write_at(frame_to_evict->fte_sup_page_table_entry->file, frame_to_evict->fte_kernel_VA_for_frame,
                          frame_to_evict->fte_sup_page_table_entry->read_bytes, frame_to_evict->fte_sup_page_table_entry->ofs);
            lock_release(&filesys_lock);
            frame_to_evict->fte_sup_page_table_entry->current_page_location = InFile;
        }
    }

    remove_and_free_frame(frame_to_evict);
}

static void remove_and_free_frame(struct frame_table_entry *frame)
{
    struct list_elem *next_clock_ptr = list_next(clock_ptr);

    list_remove(clock_ptr);
    pagedir_clear_page(frame->fte_thread->pagedir, frame->fte_VA_for_page);
    palloc_free_page(frame->fte_kernel_VA_for_frame);
    free(frame);

    clock_ptr = next_clock_ptr;
    if (clock_ptr == list_end(&frame_table))
        clock_ptr = list_begin(&frame_table);
}

void free_frame(void *frame)
{
    struct list_elem *frame_table_list_ptr;
    struct frame_table_entry *frame_table_entry_ptr;

    ASSERT(pg_ofs(frame) == 0);

    lock_acquire(&frame_table_lock);

    frame_table_list_ptr = list_begin(&frame_table);

    while (frame_table_list_ptr != list_end(&frame_table))
    {
        frame_table_entry_ptr = list_entry(frame_table_list_ptr, struct frame_table_entry, fte_elem);

        if (frame_table_entry_ptr->fte_kernel_VA_for_frame != frame)
        {
            frame_table_list_ptr = list_next(frame_table_list_ptr);
        }
        else
        {
            // clock_ptr could be dangling ptr w/o this logic
            if (frame_table_list_ptr == clock_ptr)
            {
                clock_ptr = list_next(clock_ptr);

                if (clock_ptr == list_end(&frame_table))
                {
                    clock_ptr = list_begin(&frame_table);
                }
            }

            list_remove(frame_table_list_ptr);

            palloc_free_page(frame_table_entry_ptr->fte_kernel_VA_for_frame);
            free(frame_table_entry_ptr);

            break;
        }
    }

    // there should be frame to be freed
    // ASSERT(frame_table_list_ptr != list_end(&frame_table));

    lock_release(&frame_table_lock);
}

void free_all_frame_when_process_exit(struct thread *thread_pointer)
{
    struct frame_table_entry *ft_entry_tmp;
    struct list_elem *clock_ptr_tmp;
    struct list_elem *frame_table_list_ptr;

    lock_acquire(&frame_table_lock);

    frame_table_list_ptr = list_begin(&frame_table);
    while (frame_table_list_ptr != list_end(&frame_table))
    {
        ft_entry_tmp = list_entry(frame_table_list_ptr, struct frame_table_entry, fte_elem);
        clock_ptr_tmp = NULL;

        if (ft_entry_tmp->fte_thread != thread_pointer)
        {
            frame_table_list_ptr = list_next(frame_table_list_ptr);
        }
        else
        {
            if (frame_table_list_ptr == clock_ptr)
            {
                clock_ptr = list_next(frame_table_list_ptr);
                if (clock_ptr == list_end(&frame_table))
                {
                    clock_ptr = list_begin(&frame_table);
                }
            }

            frame_table_list_ptr = list_remove(frame_table_list_ptr);
            pagedir_clear_page(ft_entry_tmp->fte_thread->pagedir, ft_entry_tmp->fte_VA_for_page);
            palloc_free_page(ft_entry_tmp->fte_kernel_VA_for_frame);
            free(ft_entry_tmp);
        }
    }

    lock_release(&frame_table_lock);
}
