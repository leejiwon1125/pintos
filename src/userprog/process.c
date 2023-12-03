#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdlib.h>
#include "vm/spt.h"
#include "vm/frame.h"
#include <hash.h>
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load(const char *file_name, void (**eip)(void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;
  // lab2 added
  char *file_name_copy;
  char *file_name_without_args;
  char *only_args;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  file_name_copy = (char *)malloc((strlen(fn_copy) + 1) * sizeof(char));
  strlcpy(file_name_copy, fn_copy, (strlen(fn_copy) + 1) * sizeof(char));
  file_name_without_args = strtok_r(file_name_copy, " ", &only_args);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name_without_args, PRI_DEFAULT, start_process, fn_copy); // child is born in here
  free(file_name_copy);

  if (tid == TID_ERROR)
  {
    palloc_free_page(fn_copy);
  }

  sema_down(&(thread_current()->sema_child_exec)); // parent have to wait for child's signal
  if (!(thread_current()->is_child_load_success))  // if load failed...
  {
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
  char *file_name = file_name_; // this contains all command line ex: "foo -a -l"
  struct intr_frame if_;
  bool success;
  // lab2 added
  //  0. make variable to use for parsing
  char *argv[100]; // max argument numebr is 100
  int argc = 0;
  char *one_word;
  char *remaining_words;
  char *file_name_for_parsing;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // parsing do here - 함수로 하려고했는데 argv랑 argc랑 같이 필요해서 여기서 함.
  // 1. make file name for parsing
  file_name_for_parsing = (char *)malloc((strlen(file_name) + 1) * sizeof(char));
  strlcpy(file_name_for_parsing, file_name, (strlen(file_name) + 1) * sizeof(char));
  // 2. do parse
  for (one_word = strtok_r(file_name_for_parsing, " ", &remaining_words); one_word != NULL; one_word = strtok_r(NULL, " ", &remaining_words))
  {
    argv[argc++] = one_word;
  }

  // 3. pass only exe file name into load
  success = load(argv[0], &if_.eip, &if_.esp);
  // 4. if load is done, it's time to set up user stack using parsed command line
  if (success)
  {
    ASSERT(if_.esp == PHYS_BASE);
    put_args_into_user_stack(&if_.esp, argc, argv);
  }
  // 5. argv[0] is copied in load function, argv[1~argc-1] is copied in user stack so its safe to free memory.
  free(file_name_for_parsing);

  /* If load failed, quit. */
  palloc_free_page(file_name);

  // 6. for exec: inform parent child's load result
  thread_current()->parent->is_child_load_success = success;
  sema_up(&(thread_current()->parent->sema_child_exec));

  if (!success)
    thread_exit();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

void put_args_into_user_stack(void **esp, int argc, char **argv)
{
  int i;
  // push real text into stack
  for (i = argc - 1; i >= 0; i--)
  {
    *esp -= (strlen(argv[i]) + 1);
    memcpy(*esp, argv[i], (strlen(argv[i]) + 1)); // used memcpy so we can free the argv in caller function of put_args_into~
    argv[i] = (uint32_t *)*esp;
  }

  // for word-align
  *esp = (void *)((uint32_t)(*esp) & 0xfffffffc);
  // mark argv[argc] to '0' into stack
  *esp -= 4;
  *(uint32_t *)*esp = 0;
  // push argv[i] into stack
  for (i = argc - 1; i >= 0; i--)
  {
    *esp -= 4;
    *(uint32_t **)*esp = argv[i];
  }
  // push 'argv'
  *esp -= 4;
  *(uint32_t **)*esp = *esp + 4;
  // push 'argc'
  *esp -= 4;
  *(uint32_t *)*esp = argc;
  // push 'fake return address'
  *esp -= 4;
  *(uint32_t *)*esp = 0;

  return;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid)
{
  // case1: child_tid was terminated by the kernel -> process_exit handles this case

  // case2: child_tid is invalid || chil_tid is not child of calling process

  // case3: process_wait has already called

  // case4: normal case

  struct thread *cur = thread_current();
  struct process *child_pcb_to_wait = NULL;
  struct list_elem *e;
  struct process *p;
  int child_exit_status;

  // case 2
  if (list_empty(&(cur->child_list)))
  {
    return -1;
  }
  // case 3
  if (cur->waiting_child_pid == child_tid)
  {
    return -1;
  }

  // try to find waiting process
  e = list_begin(&(cur->child_list));
  while (e != list_end(&(cur->child_list)))
  {
    p = list_entry(e, struct process, elem);
    if (p->tid_p == child_tid) // if child exit first then parent, p->thread_info_p might not exist anymore. let's fix struct process
    {
      child_pcb_to_wait = p;
      break;
    }
    e = list_next(e);
  }
  // case 2  printf("zxcvzxcv"); this is needed. parent child making step might be wrong
  if (child_pcb_to_wait == NULL)
  {
    return -1;
  }

  // record waiting_child_pid for process_exit and case 3
  cur->waiting_child_pid = child_tid;
  if (child_pcb_to_wait->is_parent_waiting)
  {
    return -1;
  }
  child_pcb_to_wait->is_parent_waiting = true;

  // case 4 : exit_status in struct process is equal with its in struct thread / exit_status == INIT~ mean not yet exited
  if (child_pcb_to_wait->exit_status_p == INIT_EXIT_STATUS) // it is good to use 'while' when using semaphore, but thie case, 'if' is okay
  {
    sema_down(&(cur->sema_child_exit));
  }
  cur->waiting_child_pid = -1;
  list_remove(&(child_pcb_to_wait->elem)); // TODO: add list_push_back in process_exec: the time when parent and child relation is built

  // the tcb could be removed so we have to save child process's information -> now its okay
  child_exit_status = child_pcb_to_wait->exit_status_p;
  free(child_pcb_to_wait);

  return child_exit_status;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;
  struct list_elem *e;
  struct process *p;
  struct list_elem *e_file;
  struct file_desc *p_fd;
  // lab2 added
  if (cur->exit_status == INIT_EXIT_STATUS) // case 1 in process_wait
  {
    exit(-1); // inform parent to it is abnormal process_exit. its svae to call exit because main logic on thread_exit not yet occured.
  }

  // just calling close for each fd_number that current process has. we are just customor in this situation. close will do free.
  e_file = list_begin(&(cur->fd_list));
  while (e_file != list_end(&(cur->fd_list)))
  {
    p_fd = list_entry(e_file, struct file_desc, elem);
    e_file = list_next(e_file);
    close(p_fd->fd_number); // read-bad-ptr test wrong due to this point.
  }
  // free child_list's element
  while (!list_empty(&(cur->child_list)))
  {
    e = list_pop_front(&(cur->child_list));
    p = list_entry(e, struct process, elem);
    free(p);
  }

  if (cur->executing_file)
  {
    file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }

  // lab 3 related resource free
  // 1. mmap
  munmap_when_process_exit(cur);
  // 2. frame table
  free_all_frame_when_process_exit(cur);
  // 3. sup page table
  hash_destroy(&(cur->sup_page_table), sup_page_table_destruct_func);

  // if parent is waiting for 'cur' thread to exit, signal to parent
  if (cur->parent->waiting_child_pid == cur->tid)
  {
    sema_up(&(cur->parent->sema_child_exit));
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name_, void (**eip)(void), void **esp)
{
  const char *file_name = file_name_; // save locally
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  hash_init(&thread_current()->sup_page_table, sup_page_table_hash_function, sup_page_table_less_func, NULL);

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open(file_name);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);
  t->executing_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
             Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  // file_close (file);
  lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct sup_page_table_entry *s_elem_tmp = malloc(sizeof(*s_elem_tmp));

    s_elem_tmp->file = file;
    s_elem_tmp->ofs = ofs;
    s_elem_tmp->spte_VA_for_page = upage;
    s_elem_tmp->read_bytes = page_read_bytes;
    s_elem_tmp->zero_bytes = page_zero_bytes;
    s_elem_tmp->writable = writable;

    s_elem_tmp->go_to_swap_disk_when_evict = true;
    s_elem_tmp->current_page_location = InFile;

    hash_insert(&thread_current()->sup_page_table, &s_elem_tmp->elem);

    /* Advance. */
    ofs += page_read_bytes;
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  // add in sup page table because this page could be evict too
  struct sup_page_table_entry *spt_entry = malloc(sizeof(*spt_entry));
  spt_entry->spte_VA_for_page = ((uint8_t *)PHYS_BASE) - PGSIZE;
  spt_entry->writable = true;
  spt_entry->go_to_swap_disk_when_evict = true;
  spt_entry->current_page_location = InMemory;

  hash_insert(&(thread_current()->sup_page_table), &(spt_entry->elem));

  kpage = allocate_frame(PAL_USER | PAL_ZERO);

  // caller function of allocate_frame's oblige
  struct frame_table_entry *ft_entry = malloc(sizeof(*ft_entry));
  ft_entry->fte_kernel_VA_for_frame = kpage;
  ft_entry->fte_VA_for_page = spt_entry->spte_VA_for_page;
  ft_entry->fte_thread = thread_current();
  ft_entry->fte_sup_page_table_entry = spt_entry;
  ft_entry->able_to_evict = true;

  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &(ft_entry->fte_elem));
  lock_release(&frame_table_lock);

  // kpage is always not NULL but respect original implementation.
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      free_frame(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}