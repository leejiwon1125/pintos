#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <synch.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/pagedir.h"
#include <spt.h>

struct list frame_table;
struct lock frame_table_lock;
struct list_elem * clock_ptr;

// frame_table_entry exists 'per' frame 
struct frame_table_entry
    {
        void * kernel_VA_for_frame;
        void * VA_for_page;             // this could be either kernel VA or user VA
        struct thread * thread;         // for accessing page directory
        struct sup_page_table_entry * sup_page_table_entry;

        struct list_elem frame_table_entry_elem;
    };

void frame_table_init(void);
void * allocate_frame(enum palloc_flags);
void free_frame(void *);
void free_all_frame_when_process_exit(struct thread *);

#endif /* vm/frame.h */