#include "vm/frame.h"

void frame_table_init(void)
{
    list_init(&frame_table);
    lock_init(&frame_table_lock);
    clock_ptr = NULL;
}

void * allocate_frame(enum palloc_flags flags)
{
    void * kernel_VA_for_new_frame = palloc_get_page(flags);
    struct frame_table_entry * fte_for_victim_frame = NULL;
    struct frame_table_entry * victim_frame_ptr;
    bool is_accessed;
    struct list_elem * clock_ptr_next;

    // case 1 : no eviction
    if (kernel_VA_for_new_frame != NULL) 
    {
        return kernel_VA_for_new_frame;
    }
    
    // case 2 : do eviction
    lock_acquire(&frame_table_lock);
    
    // for initial clock_ptr
    if (clock_ptr == NULL)
    {
        clock_ptr = list_begin(&frame_table);
    }

    // due to serveral fail to allocate introduce while loop
    while (kernel_VA_for_new_frame == NULL)
    {
        ASSERT(clock_ptr != list_end(&frame_table));
        // step A. find victim frame
        while(true)
        {
            victim_frame_ptr = list_entry (clock_ptr, struct frame_table_entry, frame_table_entry_elem);
            
            // use clock algorithm
            is_accessed = pagedir_is_accessed(victim_frame_ptr->thread->pagedir, victim_frame_ptr->VA_for_page)
            if (is_accessed)
            {
                pagedir_set_accessed(victim_frame_ptr->thread->pagedir, victim_frame_ptr->VA_for_page, false);
            }
            else 
            {
                fte_for_victim_frame = victim_frame_ptr;
                break;
            }

            clock_ptr = list_next(clock_ptr);

            if(clock_ptr == list_end(&frame_table))
            {
                clock_ptr = list_begin(&frame_table);
            }

        }

        // Warning: if there is no victim page, then infinite loop
        ASSERT(fte_for_victim_frame != NULL);

        // step B. have to do remedy for victim frame 
        
        ASSERT( fte_for_victim_frame ->sup_page_table_entry -> current_page_location == InMemory);

        if ( fte_for_victim_frame->sup_page_table_entry-> go_to_swap_disk_when_evict )
        {
            // goto swap disk
            fte_for_victim_frame ->sup_page_table_entry ->frame_idx_in_swap_disk = swap_out(fte_for_victim_frame ->kernel_VA_for_frame);
            fte_for_victim_frame ->sup_page_table_entry ->current_page_location = InSwapDisk;
        }
        else
        {
            // goto file
            ASSERT( fte_for_victim_frame ->VA_for_page == fte_for_victim_frame ->sup_page_table_entry ->VA_for_page);
            if(pagedir_is_dirty(fte_for_victim_frame ->thread ->pagedir, fte_for_victim_frame->VA_for_page))
            {
                lock_acquire(&filesys_lock);
                file_write_at(
                                fte_for_victim_frame ->sup_page_table_entry ->file, 
                                fte_for_victim_frame ->kernel_VA_for_frame,
                                fte_for_victim_frame ->sup_page_table_entry ->page_read_bytes,
                                fte_for_victim_frame ->sup_page_table_entry ->ofs
                            )
                lock_release(&filesys_lock);
            }
            // update spt. note that evicting page does "not" mean that freeing its spt entry but update it. 
            // we have to take care of all the 'page' that process uses.
            fte_for_victim_frame ->sup_page_table_entry ->current_page_location = InFile;
        }

        // step C. free vicitim frame
        
        //   step1. remove fte from frame table
        clock_ptr_next = list_next(clock_ptr);
        
        ASSERT(fte_for_victim_frame->frame_table_entry_elem == clock_ptr);
        list_remove(clock_ptr);
        
        clock_ptr = clock_ptr_next;
        if(clock_ptr == list_end(&frame_table))
        {
            clock_ptr = list_begin(&frame_table);
        }

        //   step2. make later access to this frame cause page fault 
        pagedir_clear_page (fte_for_victim_frame->thread->pagedir, fte_for_victim_frame->VA_for_page);

        //   step3. free resources: frame and memory for fte
        palloc_free_page(fte_for_victim_frame->kernel_VA_for_frame);
        free(fte_for_victim_frame)
        

        // try again for allocate
        kernel_VA_for_new_frame = palloc_get_page(flags);

    }

    lock_release(&frame_table_lock);

    return kernel_VA_for_new_frame;
}

// this function does not clear page for page directory. it just consider frame table.
void free_frame(void * frame)
{
    struct list_elem * frame_table_list_ptr;
    struct frame_table_entry * frame_table_entry_ptr;

    ASSERT(pg_ofs(frame) == 0);

    lock_acquire(&frame_table_lock);

    frame_table_list_ptr = list_begin(&frame_table);
    
    while(frame_table_list_ptr != list_end(&frame_table))
    {
        frame_table_entry_ptr = list_entry(frame_table_list_ptr, struct frame_table_entry, frame_table_entry_elem);

        if (frame_table_entry_ptr->kernel_VA_for_frame != frame)
        {
            frame_table_list_ptr = list_next(frame_table_list_ptr);
        }
        else 
        {
            // clock_ptr could be dangling ptr w/o this logic
            if (frame_table_list_ptr == clock_ptr)
            {
                clock_ptr = list_next(clock_ptr);

                if(clock_ptr == list_end(&frame_table))
                {
                    clock_ptr = list_begin(&frame_table);
                }

            }

            list_remove(frame_table_list_ptr);

            palloc_free_page(frame_table_entry_ptr->kernel_VA_for_frame);
            free(frame_table_entry_ptr);

            break;
        }

    }

    // there should be frame to be freed
    ASSERT(frame_table_list_ptr != list_end(&frame_table));

    lock_release(&frame_table_lock);
}

void free_all_frame_when_process_exit(struct thread * thread)
{

    struct list_elem * frame_table_list_ptr;
    struct frame_table_entry * frame_table_entry_ptr;

    lock_acquire(&frame_table_lock);

    frame_table_list_ptr = list_begin(&frame_table);
    
    while(frame_table_list_ptr != list_end(&frame_table))
    {
        frame_table_entry_ptr = list_entry(frame_table_list_ptr, struct frame_table_entry, frame_table_entry_elem);

        if (frame_table_entry_ptr->thread != thread)
        {
            frame_table_list_ptr = list_next(frame_table_list_ptr);
        }
        else 
        {
            // clock_ptr could be dangling ptr w/o this logic
            if (frame_table_list_ptr == clock_ptr)
            {
                clock_ptr = list_next(clock_ptr);

                if(clock_ptr == list_end(&frame_table))
                {
                    clock_ptr = list_begin(&frame_table);
                }

            }

            list_remove(frame_table_list_ptr);

            pagedir_clear_page(frame_table_entry_ptr->thread->pagedir, frame_table_entry_ptr->VA_for_page);
            palloc_free_page(frame_table_entry_ptr->kernel_VA_for_frame);
            free(frame_table_entry_ptr);

        }

    }

    // we should check all the frame_table
    ASSERT(frame_table_list_ptr == list_end(&frame_table));

    lock_release(&frame_table_lock);
}
