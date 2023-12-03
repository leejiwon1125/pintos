#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "vm/spt.h"
#include "vm/swap.h"
#include "threads/malloc.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

bool decide_stack_growth_and_do_if_needed(void *esp, void *addr)
{
  if (addr < esp - 32)
  {
    return false;
  }

  ASSERT(!(unsigned int)PHYS_BASE - (unsigned int)esp > (1 << 23));

  void *user_VA_for_page = (void *)((uint32_t)addr & 0xfffff000);

  if ((unsigned int)PHYS_BASE - (unsigned int)user_VA_for_page > (1 << 23))
  {
    return false;
  }

  // add in sup page table because this page could be evict too
  struct sup_page_table_entry *spt_entry = malloc(sizeof(*spt_entry));
  spt_entry->spte_VA_for_page = user_VA_for_page;
  spt_entry->writable = true;
  spt_entry->go_to_swap_disk_when_evict = true;
  spt_entry->current_page_location = InMemory;

  void *kernel_VA_for_new_frame = allocate_frame(PAL_USER | PAL_ZERO);

  // caller function of allocate_frame's oblige
  struct frame_table_entry *ft_entry = malloc(sizeof(*ft_entry));
  ft_entry->fte_kernel_VA_for_frame = kernel_VA_for_new_frame;
  ft_entry->fte_VA_for_page = spt_entry->spte_VA_for_page;
  ft_entry->fte_thread = thread_current();
  ft_entry->fte_sup_page_table_entry = spt_entry;
  ft_entry->able_to_evict = true;

  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &(ft_entry->fte_elem));
  lock_release(&frame_table_lock);

  bool success = install_page(user_VA_for_page, kernel_VA_for_new_frame, true);
  if (success)
  {
    // this function just decide whether stack growth is needed. -> does not change esp
    hash_insert(&(thread_current()->sup_page_table), &(spt_entry->elem));
    return true;
  }
  else
  {
    free(spt_entry);
    free_frame(kernel_VA_for_new_frame);
    return false;
  }
}

bool allocate_frame_for_syscall_if_needed(struct hash_elem *to_find, void *virtual_page_addr)
{
  struct sup_page_table_entry *fault_page_spte = hash_entry(to_find, struct sup_page_table_entry, elem);

  if (pagedir_get_page(thread_current()->pagedir, virtual_page_addr) == NULL)
  {
    void *kernel_VA_for_frame = NULL;
    struct frame_table_entry *ft_entry = NULL;

    if (fault_page_spte->current_page_location != InMemory)
    {
      kernel_VA_for_frame = allocate_frame(PAL_USER);

      ft_entry = malloc(sizeof(*ft_entry));
      ft_entry->fte_kernel_VA_for_frame = kernel_VA_for_frame;
      ft_entry->fte_VA_for_page = virtual_page_addr;
      ft_entry->fte_thread = thread_current();
      ft_entry->fte_sup_page_table_entry = fault_page_spte;
      ft_entry->able_to_evict = false;

      if (fault_page_spte->current_page_location != InMemory)
      {
        kernel_VA_for_frame = allocate_frame(PAL_USER);

        ft_entry = malloc(sizeof(*ft_entry));
        ft_entry->fte_kernel_VA_for_frame = kernel_VA_for_frame;
        ft_entry->fte_VA_for_page = virtual_page_addr;
        ft_entry->fte_thread = thread_current();
        ft_entry->fte_sup_page_table_entry = fault_page_spte;
        ft_entry->able_to_evict = false;

        if (fault_page_spte->current_page_location == InFile)
        {
          lock_acquire(&filesys_lock);
          file_seek(fault_page_spte->file, fault_page_spte->ofs);
          file_read(fault_page_spte->file, ft_entry->fte_kernel_VA_for_frame, fault_page_spte->read_bytes);
          lock_release(&filesys_lock);

          memset(ft_entry->fte_kernel_VA_for_frame + fault_page_spte->read_bytes, 0, fault_page_spte->zero_bytes);
        }
        else if (fault_page_spte->current_page_location == InSwapDisk)
        {
          swap_in(ft_entry->fte_kernel_VA_for_frame, fault_page_spte->frame_idx_in_swap_disk);
        }
      }

      fault_page_spte->current_page_location = InMemory;

      lock_acquire(&frame_table_lock);
      list_push_back(&frame_table, &ft_entry->fte_elem);
      lock_release(&frame_table_lock);

      if (!pagedir_set_page(ft_entry->fte_thread->pagedir, ft_entry->fte_VA_for_page, ft_entry->fte_kernel_VA_for_frame, fault_page_spte->writable))
      {
        lock_acquire(&frame_table_lock);

        struct list_elem *clock_ptr_tmp = NULL;
        if (clock_ptr == &ft_entry->fte_elem)
          clock_ptr_tmp = list_next(&ft_entry->fte_elem);

        list_remove(&ft_entry->fte_elem);
        free(ft_entry);

        if (clock_ptr_tmp)
        {
          clock_ptr = clock_ptr_tmp;
          if (clock_ptr == list_end(&frame_table))
            clock_ptr = list_begin(&frame_table);
        }

        lock_release(&frame_table_lock);
        return false;
      }
      ft_entry->able_to_evict = true;
    }
  }

  return true;
}

void check_address(void *esp, void *addr, unsigned size)
{
  void *temp;
  int i;

  for (i = 0; i < size; i++)
  {
    if ((addr + i) == NULL)
    {
      exit(-1);
    }
  }
  if (addr + size >= PHYS_BASE || addr < (void *)(0x08048000))
  {
    exit(-1);
  }

  for (i = 0; i <= size; i++)
  {
    void *user_VA_for_page = (void *)((uint32_t)(addr + i) & 0xfffff000);
    struct sup_page_table_entry *spt_entry_tmp = malloc(sizeof(*spt_entry_tmp));
    spt_entry_tmp->spte_VA_for_page = user_VA_for_page;
    struct hash_elem *spt_hash_elem = hash_find(&thread_current()->sup_page_table, &spt_entry_tmp->elem);

    free(spt_entry_tmp);
    if (spt_hash_elem != NULL)
    {
      if (!allocate_frame_for_syscall_if_needed(spt_hash_elem, user_VA_for_page))
        exit(-1);
    }
    else
    {
      if (!decide_stack_growth_and_do_if_needed(esp, addr + i))
      {
        exit(-1);
      }
    }
  }
}

bool check_readable(void *esp, void *buffer, unsigned size)
{
  int i;
  void *VA_for_page;
  struct sup_page_table_entry *spt_entry_tmp;
  struct hash_elem *spt_hash_elem;
  struct sup_page_table_entry *page_to_write;
  for (i = 0; i <= size; i++)
  {
    VA_for_page = (void *)((uint32_t)(buffer + i) & 0xfffff000);
    spt_entry_tmp = malloc(sizeof(*spt_entry_tmp));
    spt_entry_tmp->spte_VA_for_page = VA_for_page;
    spt_hash_elem = hash_find(&thread_current()->sup_page_table, &spt_entry_tmp->elem);

    free(spt_entry_tmp);
    if (spt_hash_elem == NULL)
      return decide_stack_growth_and_do_if_needed(esp, buffer + i);
    else if (!allocate_frame_for_syscall_if_needed(spt_hash_elem, VA_for_page))
      return false;
    else
    {
      page_to_write = hash_entry(spt_hash_elem, struct sup_page_table_entry, elem);
      if (!page_to_write->writable)
        return false;
    }
  }

  return true;
}

bool check_writable(void *esp, void *buffer, unsigned size)
{
  int i;
  void *VA_for_page;
  struct sup_page_table_entry *spt_entry_tmp;
  struct hash_elem *spt_hash_elem;
  struct sup_page_table_entry *page_to_write;
  for (i = 0; i <= size; i++)
  {
    VA_for_page = (void *)((uint32_t)(buffer + i) & 0xfffff000);
    spt_entry_tmp = malloc(sizeof(*spt_entry_tmp));
    spt_entry_tmp->spte_VA_for_page = VA_for_page;
    spt_hash_elem = hash_find(&thread_current()->sup_page_table, &spt_entry_tmp->elem);

    free(spt_entry_tmp);
    if (spt_hash_elem == NULL)
      return decide_stack_growth_and_do_if_needed(esp, buffer + i);
    else if (!allocate_frame_for_syscall_if_needed(spt_hash_elem, VA_for_page))
      return false;
  }

  return true;
}

struct file_desc *
get_file_desc(struct thread *t, int fd_number)
{
  struct list *fd_list = &(t->fd_list);
  struct list_elem *e;
  struct file_desc *e_f;

  // no such fd_number in thread t
  if (list_empty(fd_list))
  {
    return NULL;
  }

  // try to find fd_number
  e = list_begin(fd_list);
  while (e != list_end(fd_list))
  {
    e_f = list_entry(e, struct file_desc, elem);
    if (e_f->fd_number == fd_number)
    {
      return e_f;
    }
    e = list_next(e);
  }

  // no such fd_number in thread t
  return NULL;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  thread_current()->esp = f->esp;
  check_address(f->esp, f->esp, 4);

  switch (*(uint32_t *)(f->esp)) // syscall number
  {
  case SYS_HALT:
  {
    halt();
    break;
  }
  case SYS_EXIT:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));

    exit(*(int *)(f->esp + 4));
    break;
  }
  case SYS_EXEC:
  {
    check_address(f->esp, f->esp + 4, sizeof(char *));

    check_address(f->esp, *(char **)(f->esp + 4), sizeof(char *));

    f->eax = exec(*(const char **)(f->esp + 4));
    break;
  }
  case SYS_WAIT:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));

    f->eax = wait(*(int *)(f->esp + 4)); // pid_t == int
    break;
  }
  case SYS_CREATE:
  {
    check_address(f->esp, f->esp + 4, sizeof(char *));
    check_address(f->esp, f->esp + 8, sizeof(unsigned));

    // f->esp+4 == address of 'char * file' in "stack".
    // we have to check_address not just stack's address
    // but also char * file 's pointing address.
    check_address(f->esp, *(char **)(f->esp + 4), sizeof(char *));

    f->eax = create(
        *(const char **)(f->esp + 4),
        *(unsigned *)(f->esp + 8));
    break;
  }
  case SYS_REMOVE:
  {
    check_address(f->esp, f->esp + 4, sizeof(char *));

    check_address(f->esp, *(char **)(f->esp + 4), sizeof(char *));

    f->eax = remove(*(const char **)(f->esp + 4));
    break;
  }
  case SYS_OPEN:
  {
    check_address(f->esp, f->esp + 4, sizeof(char *));

    check_address(f->esp, *(char **)(f->esp + 4), sizeof(char *));

    f->eax = open(*(const char **)(f->esp + 4));
    break;
  }
  case SYS_FILESIZE:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));

    f->eax = filesize(*(int *)(f->esp + 4));
    break;
  }
  case SYS_READ:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));
    check_address(f->esp, f->esp + 8, sizeof(void *));
    check_address(f->esp, f->esp + 12, sizeof(unsigned));

    check_address(f->esp, *(void **)(f->esp + 8), sizeof(void *));

    f->eax = read(f->esp, *(int *)((f->esp) + 4), *(char **)((f->esp) + 8), *(unsigned *)((f->esp) + 12));
    break;
  }
  case SYS_WRITE:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));
    check_address(f->esp, f->esp + 8, sizeof(void *));
    check_address(f->esp, f->esp + 12, sizeof(unsigned));

    check_address(f->esp, *(void **)(f->esp + 8), sizeof(void *));

    f->eax = write(f->esp, *(int *)((f->esp) + 4), *(char **)((f->esp) + 8), *(unsigned *)((f->esp) + 12));
    break;
  }
  case SYS_SEEK:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));
    check_address(f->esp, f->esp + 8, sizeof(unsigned));

    seek(
        *(int *)(f->esp + 4),
        *(unsigned *)(f->esp + 8));
    break;
  }
  case SYS_TELL:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));

    f->eax = tell(*(int *)(f->esp + 4));
    break;
  }
  case SYS_CLOSE:
  {
    check_address(f->esp, f->esp + 4, sizeof(int));

    close(*(int *)(f->esp + 4));
    break;
  }
  case SYS_MMAP:
  {
    check_address(f->esp, (f->esp) + 4, 8);
    f->eax = mmap(*(int *)(f->esp + 4), *(char **)(f->esp + 8));
    break;
  }

  case SYS_MUNMAP:
  {
    check_address(f->esp, (f->esp) + 4, 4);
    munmap(*(mapid_t *)(f->esp + 4));
    break;
  }
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *t = thread_current();
  struct process *cur_process; // current process in the view of parent
  struct list *parent_s_child_list = &(t->parent->child_list);
  struct list_elem *e;

  // 1. save status into tcb
  t->exit_status = status;
  // 2. update exit_status info to parent's child list : this is needed because we use other then struct thread
  for (e = list_begin(parent_s_child_list); e != list_end(parent_s_child_list); e = list_next(e))
  {
    cur_process = list_entry(e, struct process, elem);
    if (cur_process->tid_p == t->tid)
    {
      cur_process->exit_status_p = status;
      break;
    }
  }
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit(); // thread_exit -> process_exit : free resource
}

int exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait(int pid)
{
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool remove(const char *file)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int open(const char *file)
{
  struct file_desc *fd = malloc(sizeof(*fd));
  struct thread *cur = thread_current();
  struct file *opened_file;

  lock_acquire(&filesys_lock);
  opened_file = filesys_open(file);
  lock_release(&filesys_lock);

  if (opened_file == NULL)
  {
    return -1;
  }

  // protect next_fd_number and fd_list: use lock

  fd->fd_number = cur->next_fd_number;
  (cur->next_fd_number)++;

  fd->opened_file = opened_file;

  list_push_back(&(cur->fd_list), &(fd->elem));

  return fd->fd_number;
}

int filesize(int fd)
{
  int file_size;
  struct file_desc *fd_found = get_file_desc(thread_current(), fd);

  if (fd_found == NULL) // No such fd in thread_current for debugging purpose
  {
    return -1;
  }

  lock_acquire(&filesys_lock);
  file_size = file_length(fd_found->opened_file);
  lock_release(&filesys_lock);
  return file_size;
}

int read(void *esp, int fd, void *buffer, unsigned size)
{
  int i;
  int cnt_bytes_read = 0;
  struct file_desc *fd_found;
  if (!check_readable(esp, buffer, size))
  {
    exit(-1);
  }

  // branch with using keyboard or not
  if (fd == 0)
  {
    for (i = 0; i < size; i++)
    {
      *((char *)buffer + i) = input_getc(); // gives one byte
      cnt_bytes_read++;
    }
    return cnt_bytes_read;
  }
  else
  {
    fd_found = get_file_desc(thread_current(), fd);
    if (fd_found == NULL)
    {
      return -1;
    }

    lock_acquire(&filesys_lock);
    cnt_bytes_read = file_read(fd_found->opened_file, buffer, size);
    lock_release(&filesys_lock);
    return cnt_bytes_read;
  }
}

int write(void *esp, int fd, const void *buffer, unsigned size)
{
  int i;
  int cnt_bytes_written = 0;
  struct file_desc *fd_found;

  if (!check_writable(esp, buffer, size))
  {
    exit(-1);
  }

  // branch with console output or not
  if (fd == 1)
  {
    putbuf(buffer, size);
    cnt_bytes_written = size;
    return cnt_bytes_written;
  }
  else
  {
    fd_found = get_file_desc(thread_current(), fd);
    if (fd_found == NULL) // No such fd in thread_current for debugging purpose
    {
      return -1;
    }

    lock_acquire(&filesys_lock);
    cnt_bytes_written = file_write(fd_found->opened_file, buffer, size);
    lock_release(&filesys_lock);
    return cnt_bytes_written;
  }
}

void seek(int fd, unsigned position)
{
  struct file_desc *fd_found = get_file_desc(thread_current(), fd);
  if (fd_found == NULL) // No such fd in thread_current for debugging purpose
  {
    return;
  }

  lock_acquire(&filesys_lock);
  file_seek(fd_found->opened_file, position);
  lock_release(&filesys_lock);
}

unsigned
tell(int fd)
{
  int position;
  struct file_desc *fd_found = get_file_desc(thread_current(), fd);
  if (fd_found == NULL) // No such fd in thread_current for debugging purpose
  {
    return -1;
  }

  lock_acquire(&filesys_lock);
  position = file_tell(fd_found->opened_file);
  lock_release(&filesys_lock);
  return position;
}

void close(int fd)
{
  struct file_desc *fd_found = get_file_desc(thread_current(), fd);
  if (fd_found == NULL) // No such fd in thread_current for debugging purpose
  {
    return;
  }
  lock_acquire(&filesys_lock);
  file_close(fd_found->opened_file);
  lock_release(&filesys_lock);
  // for programmer's perspective at given file.c and filesys.c etc, file_desc free is needed because its made by us.
  list_remove(&(fd_found->elem));
  free(fd_found);
}

mapid_t
mmap(int fd, void *addr)
{
  // step 1. basic inspect

  if (pg_ofs(addr) != 0 || addr == 0 || fd == 0 || fd == 1)
  {
    // case 2: not page-aligned
    // case 4: address 0
    // case 5: fd 0, 1
    return -1;
  }

  struct thread *t = thread_current();
  struct file *file;
  off_t bytes_to_read;
  struct file_desc *fd_found = get_file_desc(t, fd);

  if (fd_found == NULL) // No such fd in thread_current for debugging purpose
  {
    return -1;
  }

  lock_acquire(&filesys_lock);
  file = file_reopen(fd_found->opened_file);
  bytes_to_read = file_length(file);

  if (bytes_to_read == 0)
  {
    // case 1: zero bytes
    file_close(file);
    lock_release(&filesys_lock);
    return -1;
  }

  lock_release(&filesys_lock);

  // step 2. add info into sup page table for lazy loading

  off_t ofs = 0;
  void *upage = addr;
  int number_of_pages_used = 0;

  int i = 0;

  while (bytes_to_read > 0)
  {
    struct sup_page_table_entry *s_elem_tmp2 = malloc(sizeof(*s_elem_tmp2));
    s_elem_tmp2->spte_VA_for_page = upage;
    struct hash_elem *spt_hash_elem = hash_find(&thread_current()->sup_page_table, &s_elem_tmp2->elem);
    free(s_elem_tmp2);

    if (spt_hash_elem != NULL || (addr >= PHYS_BASE || addr < (void *)(0x08048000)))
    {
      // case 3: overlaps with any existing set of mapped pages.
      // case +: it should be only in user VA because mmapp is per process

      for (i = 0; i < number_of_pages_used; i++)
      {
        void *VA_to_remove = addr + PGSIZE * i;
        struct sup_page_table_entry *s_elem_tmp3 = malloc(sizeof(*s_elem_tmp3));
        s_elem_tmp3->spte_VA_for_page = VA_to_remove;
        struct hash_elem *spt_hash_elem_to_remove = hash_find(&thread_current()->sup_page_table, &s_elem_tmp3->elem);
        free(s_elem_tmp3);

        sup_page_table_destruct_func(spt_hash_elem_to_remove, NULL);
      }

      lock_acquire(&filesys_lock);
      file_close(file);
      lock_release(&filesys_lock);

      return -1;
    }

    // calculate how to fill this page
    size_t page_read_bytes = bytes_to_read < PGSIZE ? bytes_to_read : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    // for lazy loading
    struct sup_page_table_entry *spt_entry = malloc(sizeof(*spt_entry));

    spt_entry->file = file;
    spt_entry->ofs = ofs;
    spt_entry->spte_VA_for_page = upage;
    spt_entry->read_bytes = page_read_bytes;
    spt_entry->zero_bytes = page_zero_bytes;
    spt_entry->writable = true;
    spt_entry->go_to_swap_disk_when_evict = false;
    spt_entry->current_page_location = InFile;

    hash_insert(&(t->sup_page_table), &(spt_entry->elem));

    // for iteration
    ofs += page_read_bytes;
    bytes_to_read -= page_read_bytes;
    upage += PGSIZE;

    number_of_pages_used++;
  }

  ASSERT(bytes_to_read == 0);

  // step 3. add info into mmaped_file_list
  struct mmap_file *mmap_file = malloc(sizeof(*mmap_file));
  mmap_file->mapping_id = t->next_mmapped_file_number;
  (t->next_mmapped_file_number)++;
  mmap_file->mmap_VA_for_page = addr;
  mmap_file->number_of_pages_using = number_of_pages_used;

  // no need lock becuase this is system call
  list_push_back(&(t->mmap_file_list), &(mmap_file->elem));
  return mmap_file->mapping_id;
}

void munmap(mapid_t mapping)
{
  struct list_elem *list_tmp = list_begin(&thread_current()->mmap_file_list);
  struct mmap_file *mmap_file_tmp = NULL;
  struct file *file;
  struct sup_page_table_entry *spt_entry_tmp;
  struct hash_elem *hash_elem_tmp;
  struct sup_page_table_entry *spt_entry;
  int i;
  while (list_tmp != list_end(&thread_current()->mmap_file_list))
  {
    mmap_file_tmp = list_entry(list_tmp, struct mmap_file, elem);
    if (mmap_file_tmp->mapping_id == mapping)
      break;
    list_tmp = list_next(list_tmp);
  }
  if (mmap_file_tmp == NULL)
    exit(-1);

  for (i = 0; i < (mmap_file_tmp->number_of_pages_using); i++)
  {
    spt_entry_tmp = malloc(sizeof(*spt_entry_tmp));
    spt_entry_tmp->spte_VA_for_page = (mmap_file_tmp->mmap_VA_for_page) + i * PGSIZE;
    hash_elem_tmp = hash_find(&thread_current()->sup_page_table, &spt_entry_tmp->elem);
    spt_entry = hash_entry(hash_elem_tmp, struct sup_page_table_entry, elem);

    lock_acquire(&frame_table_lock);
    struct list_elem *mmap_file_list_ptr = list_begin(&frame_table);

    void *fte_kernel_VA_for_frame = NULL;
    while (mmap_file_list_ptr != list_end(&frame_table))
    {
      struct frame_table_entry *ft_entry_tmp = list_entry(mmap_file_list_ptr, struct frame_table_entry, fte_elem);
      if ((ft_entry_tmp->fte_thread != thread_current() || ft_entry_tmp->fte_VA_for_page != spt_entry->spte_VA_for_page))
      {
        mmap_file_list_ptr = list_next(mmap_file_list_ptr);
      }
      else
      {
        fte_kernel_VA_for_frame = ft_entry_tmp->fte_kernel_VA_for_frame;
        break;
      }
    }
    lock_release(&frame_table_lock);

    file = spt_entry->file;
    if (pagedir_is_dirty(thread_current()->pagedir, spt_entry->spte_VA_for_page))
    {
      lock_acquire(&filesys_lock);
      file_write_at(file, fte_kernel_VA_for_frame, spt_entry->read_bytes, spt_entry->ofs);
      lock_release(&filesys_lock);
    }
    pagedir_clear_page(thread_current()->pagedir, spt_entry->spte_VA_for_page);
    free(spt_entry_tmp);
    free_frame(fte_kernel_VA_for_frame);
    sup_page_table_destruct_func(hash_elem_tmp, NULL);
  }

  list_remove(&mmap_file_tmp->elem);
  free(mmap_file_tmp);
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
}

void munmap_when_process_exit(struct thread *thread)
{
  struct list_elem *mmap_file_list_ptr = list_begin(&(thread->mmap_file_list));

  while (mmap_file_list_ptr != list_end(&(thread->mmap_file_list)))
  {
    struct mmap_file *mmap_file = list_entry(mmap_file_list_ptr, struct mmap_file, elem);
    mmap_file_list_ptr = list_next(mmap_file_list_ptr);
    munmap(mmap_file->mapping_id);
  }
}