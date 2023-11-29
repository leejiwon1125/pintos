#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/spt.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  
   ASSERT(not_present);

   if( fault_addr >= PHYS_BASE || fault_addr < (void*)(0x08048000) )
   {
      // invalid 2: page lies within kernel VM
      exit(-1);
   }

   void * VA_for_faulted_page = (void *)((unsigned)fault_addr & 0xfffff000);
   struct hash_elem * spt_hash_elem = sup_page_table_find_hash_elem(&(thread_current()->sup_page_table), VA_for_faulted_page);
      
   if(spt_hash_elem == NULL)
   {
      // invalid 1: user process doesn't want this virtual address(faulted address)
      // this could be the place where stack growth is needed.
      if(user)
      {
         bool is_stack_growing_case = decide_stack_growth_and_do_if_needed(f->esp, fault_addr);
         if (!is_stack_growing_case)
         {
            exit(-1);
         }
      }
      else
      {
         // grow only user stack
         exit(-1);
      }

   }
   else
   {
      // loading should be do in here. no more lazy

      // allocate memory (== frame) for loaded page
      struct sup_page_table_entry * spt_entry = hash_entry (spt_hash_elem, struct sup_page_table_entry, spt_entry_elem);

      if( (write == true) && (spt_entry->writable == false) )
      {
         //invalid 3: attempt to wrtie to a read-only page
         exit(-1);
      }

      void * kernel_VA_for_frame = allocate_frame(PAL_USER);
      
      // thanks to eviction, we always get frame
      ASSERT(kernel_VA_for_frame != NULL);

      // obligation of caller of allocate_frame function: add page table entry
      struct frame_table_entry * ft_entry = malloc(sizeof(*ft_entry));
      ft_entry->kernel_VA_for_frame = kernel_VA_for_frame;
      ft_entry->VA_for_page = VA_for_faulted_page;
      ft_entry->thread = thread_current();
      ft_entry->sup_page_table_entry = spt_entry;

      // pick one situation: 1. lazy load from file / 2. just get page from swap disk
      switch(spt_entry ->current_page_location)
      {
         case InFile:
         {
            // do loading
            lock_acquire(&filesys_lock);
            file_seek(spt_entry->file, spt_entry->ofs);
            file_read(spt_entry->file, kernel_VA_for_frame, spt_entry->page_zero_bytes);
            lock_release(&filesys_lock);
            memset(kernel_VA_for_frame + spt_entry->page_read_bytes, 0, spt_entry->page_zero_bytes);
            break;
         }  
         case InSwapDisk:
         {
            swap_in(kernel_VA_for_frame, spt_entry ->frame_idx_in_swap_disk);
            break;
         }
         case InMemory:
         {
            ASSERT(false);
         }
      }
      
      spt_entry ->current_page_location = InMemory;

      // going frame table after loading might be more safe
      lock_acquire(&frame_table_lock);
      list_push_back(&frame_table, &(ft_entry->frame_table_entry_elem));
      lock_release(&frame_table_lock);

      // VA_for_faulted_page should be clean becuase...
      // we reserved that page using spt (in load_segment) instead of real loading
      ASSERT( pagedir_get_page(&(thread_current()->pagedir), VA_for_faulted_page) == NULL );

      // Add the page to the process's address space.
      install_page(VA_for_faulted_page, kernel_VA_for_frame, spt_entry->writable);


   }

}

