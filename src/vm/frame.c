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
        // TODO : implement write back logic

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

// this function does not clear page for page directory
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
