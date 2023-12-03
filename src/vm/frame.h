#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/spt.h"
#include "vm/swap.h"

struct list frame_table;
struct lock frame_table_lock;
struct list_elem *clock_ptr;

struct frame_table_entry
{
    void *fte_kernel_VA_for_frame;
    void *fte_VA_for_page;
    struct thread *fte_thread;
    struct sup_page_table_entry *fte_sup_page_table_entry;
    bool able_to_evict;

    struct list_elem fte_elem;
};

void frame_table_init(void);
void *allocate_frame(enum palloc_flags);
void free_frame(void *frame);
void free_all_frame_when_process_exit(struct thread *);

#endif /* vm/frame.h */