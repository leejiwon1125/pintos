#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include <spt.h>
#include <frame.h>
#include <process.h>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

bool 
decide_stack_growth_and_do_if_needed (void * esp, void * addr)
{
  // at least this condition should be fulfilled to be candidate of stack growth access
  if (!( (addr == esp -4)||(addr == esp -32) ))
  {
    return false;
  }

  ASSERT( !(unsigned int)PHYS_BASE - (unsigned int)esp > (1<<23) )
  
  void * user_VA_for_page = (void *)((unsigned int)addr & 0xfffff000);

  if ((unsigned int)PHYS_BASE - (unsigned int)user_VA_for_page > (1<<23))
  {
    return false;
  }

  // add in sup page table because this page could be evict too
  struct sup_page_table_entry * spt_entry = malloc(sizeof(*spt_entry));
  spt_entry ->VA_for_page = user_VA_for_page;
  spt_entry ->writable = true;
  spt_entry ->go_to_swap_disk_when_evict = true;
  spt_entry ->current_page_location = InMemory;
  
  void * kernel_VA_for_new_frame = allocate_frame (PAL_USER | PAL_ZERO);

  // caller function of allocate_frame's oblige
  struct frame_table_entry * ft_entry = malloc(sizeof(*ft_entry));
  ft_entry->kernel_VA_for_frame = kernel_VA_for_new_frame;
  ft_entry->VA_for_page = spt_entry->VA_for_page;
  ft_entry->thread = thread_current();
  ft_entry->sup_page_table_entry = spt_entry;

  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &(ft_entry->frame_table_entry_elem));
  lock_release(&frame_table_lock);

  bool success = install_page (user_VA_for_page, kernel_VA_for_new_frame, true);
  if (success)
  {
    // this function just decide whether stack growth is needed. -> does not change esp
    hash_insert(&(thread_current() -> sup_page_table), &(spt_entry -> spt_entry_elem));
    return true;
  }
  else
  {
    free(spt_entry);
    free_frame (kernel_VA_for_new_frame);
    return false;
  }
}

static void 
check_address (const void *addr, unsigned size, const void * esp)
{
  int i;

  // case 1: null pointer
  for (i=0;i<size;i++)
  {
    if ( (addr+i) == NULL )
    {
      exit(-1);
    }
  }
  
  // case 2: outside of 0x08048000 ~ PHYS_BASE
  if(addr >= PHYS_BASE || addr < (void*)(0x08048000) )
  {
    exit(-1);
  }

  if((addr+size-1) >= PHYS_BASE || (addr) < (void*)(0x08048000) )
  {
    exit(-1);
  }

  // case 3: unmapped
  for (i=0; i<size; i++)
  {
    // this is not the case in lab3
    //if(pagedir_get_page(thread_current()->pagedir, addr+i) == NULL) //lookup_page returns null pointer if addr is unmapped
    //{
    //  exit(-1);
    //}
    void * user_VA_for_page = (void *)((unsigned)(addr + i) & 0xfffff000);
    struct hash_elem * spt_hash_elem = sup_page_table_find_hash_elem(&(thread_current()->sup_page_table), user_VA_for_page);

    if (spt_hash_elem == NULL)
    {
      // case 1 : if unmapped -> check if stack growth is needed
      if(!decide_stack_growth_and_do_if_needed(esp, addr + i))
      {
        exit(-1);
      }
    }
    else 
    {
      // case 2 : if mapped -> it might be 'not' in frame but in page.
      // for system call, make it in physical memory to work properly.
      // TODO: function like page fault ... 
      //       related VA's information is definitly in spt.

    }

  }


    
}

static struct file_desc *
get_file_desc(struct thread * t, int fd_number)
{
  struct list * fd_list = &(t->fd_list);
  struct list_elem * e;
  struct file_desc * e_f;

  // no such fd_number in thread t
  if (list_empty(fd_list))
  {
    return NULL;
  }

  // try to find fd_number
  e = list_begin(fd_list);
  while(e != list_end(fd_list))
  {
    e_f = list_entry(e, struct file_desc, elem_f);
    if(e_f->fd_number == fd_number)
    {
      return e_f;
    }
    e = list_next(e);
  }

  // no such fd_number in thread t
  return NULL;

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  check_address (f->esp, 4, f->esp);
  
  switch (*(uint32_t *) (f->esp)) // syscall number
  {
    case SYS_HALT:
    {
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      check_address (f->esp + 4, sizeof(int), f->esp);

      exit (*(int *)(f->esp + 4));
      break;
    }
    case SYS_EXEC:
    {
      check_address (f->esp + 4, sizeof(char*), f->esp);

      check_address (*(char **)(f->esp + 4), sizeof(char*), f->esp);

      f->eax = exec (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_WAIT:
    {
      check_address (f->esp + 4, sizeof(int), f->esp);

      f->eax = wait (*(int *)(f->esp + 4)); //pid_t == int
      break;
    }
    case SYS_CREATE:
    {
      check_address (f->esp + 4, sizeof(char*), f->esp);
      check_address (f->esp + 8, sizeof(unsigned), f->esp);

      // f->esp+4 == address of 'char * file' in "stack". 
      // we have to check_address not just stack's address
      // but also char * file 's pointing address.
      check_address (*(char **)(f->esp + 4), sizeof(char*), f->esp); 

      f->eax = create (
          *(const char **)(f->esp + 4),
          *(unsigned *)(f->esp + 8)
          );
      break;
    }
    case SYS_REMOVE:
    {
      check_address (f->esp + 4, sizeof(char*), f->esp);

      check_address (*(char **)(f->esp + 4), sizeof(char*), f->esp); 

      f->eax = remove (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_OPEN:
    {
      check_address (f->esp + 4, sizeof(char*), f->esp);

      check_address (*(char **)(f->esp + 4), sizeof(char*), f->esp); 

      f->eax = open (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_FILESIZE:
    {
      check_address (f->esp + 4,sizeof(int), f->esp);

      f->eax = filesize (*(int *)(f->esp + 4));
      break;
    }
    case SYS_READ:
    {
      check_address (f->esp + 4,sizeof(int), f->esp);
      check_address (f->esp + 8,sizeof(void*), f->esp);
      check_address (f->esp + 12,sizeof(unsigned), f->esp);

      check_address (*(void **)(f->esp + 8), sizeof(void*), f->esp); 

      f->eax = read (
          *(int *)(f->esp + 4),
          *(void **)(f->esp + 8) ,
          *(unsigned *)(f->esp + 12)
          );
      break;
    }
    case SYS_WRITE:
    {
      check_address (f->esp + 4,sizeof(int), f->esp);
      check_address (f->esp + 8,sizeof(void*), f->esp);
      check_address (f->esp + 12,sizeof(unsigned), f->esp);

      check_address (*(void **)(f->esp + 8), sizeof(void*), f->esp); 

      f->eax = write (
          *(int *)(f->esp + 4),
          *(const void **)(f->esp + 8),
          *(unsigned *)(f->esp + 12)
          );
      break;
    }
    case SYS_SEEK:
    {
      check_address (f->esp + 4, sizeof(int), f->esp);
      check_address (f->esp + 8, sizeof(unsigned), f->esp);

      seek (
          *(int *)(f->esp + 4),
          *(unsigned *)(f->esp + 8)
          );
      break;
    }
    case SYS_TELL:
    {
      check_address (f->esp + 4,sizeof(int), f->esp);

      f->eax = tell (*(int *)(f->esp + 4));
      break;
    }
    case SYS_CLOSE:
    {
      check_address (f->esp + 4,sizeof(int), f->esp);

      close (*(int *)(f->esp +  4));
      break;
    }
  }
}


void 
halt (void)
{
  shutdown_power_off ();
}

void 
exit (int status)
{
  struct thread * t = thread_current ();
  struct process * cur_process; //current process in the view of parent
  struct list * parent_s_child_list = &(t->parent->child_list);
  struct list_elem * e;

  //1. save status into tcb
  t->exit_status = status;
  //2. update exit_status info to parent's child list : this is needed because we use other then struct thread 
  for (e = list_begin(parent_s_child_list); e != list_end(parent_s_child_list); e = list_next(e))
  {
    cur_process = list_entry(e,struct process, elem_p);
    if (cur_process->tid_p == t->tid)
    {
      cur_process->exit_status_p = status;
      break;
    }
  }
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();  // thread_exit -> process_exit : free resource
}

int 
exec (const char *cmd_line)
{
  return process_execute (cmd_line);
}

int 
wait (int pid)
{
  return process_wait (pid);
}

bool 
create (const char *file, unsigned initial_size)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_create (file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool 
remove (const char *file)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int 
open (const char *file)
{
  struct file_desc * fd = malloc(sizeof(*fd)); 
  struct thread * cur = thread_current ();
  struct file * opened_file;
  
  lock_acquire(&filesys_lock);
  opened_file = filesys_open(file);
  lock_release(&filesys_lock);

  if (opened_file == NULL)
  {
    return -1;
  }

  // protect next_fd_number and fd_list: use lock
  //lock_acquire(&(cur->fd_number_lock));
  
  fd->fd_number = cur->next_fd_number;
  (cur->next_fd_number)++;
  
  fd->opened_file = opened_file;

  list_push_back(&(cur->fd_list),&(fd->elem_f));

  //lock_release(&(cur->fd_number_lock));
  
  return fd->fd_number;

}

int 
filesize (int fd)
{
  int file_size;
  struct file_desc * fd_found = get_file_desc(thread_current(), fd);
  
  if (fd_found == NULL) //No such fd in thread_current for debugging purpose
  {
    return -1;
  }

  lock_acquire(&filesys_lock);
  file_size = file_length(fd_found->opened_file);
  lock_release(&filesys_lock);
  return file_size;
}

int 
read (int fd, void *buffer, unsigned size)
{
  int i;
  int cnt_bytes_read = 0;
  struct file_desc * fd_found;

  // branch with using keyboard or not
  if (fd == 0)
  {
    for (i=0; i< size; i++)
    {
      *((char *)buffer + i) = input_getc (); //gives one byte
      cnt_bytes_read++;
    }
    return cnt_bytes_read;
  }
  else 
  {
    fd_found = get_file_desc (thread_current(), fd);
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

int 
write (int fd, const void *buffer, unsigned size)
{
  int i;
  int cnt_bytes_written = 0;
  struct file_desc * fd_found;

  // branch with console output or not
  if (fd == 1)
  {
    putbuf(buffer, size);
    cnt_bytes_written = size;
    return cnt_bytes_written;
  }
  else
  {
    fd_found = get_file_desc (thread_current(), fd);
    if (fd_found == NULL) //No such fd in thread_current for debugging purpose
    {
      return -1;
    }

    lock_acquire(&filesys_lock);
    cnt_bytes_written = file_write(fd_found->opened_file, buffer, size);
    lock_release(&filesys_lock);
    return cnt_bytes_written;
  }

}

void 
seek (int fd, unsigned position)
{
  struct file_desc * fd_found = get_file_desc (thread_current(), fd);
  if (fd_found == NULL) //No such fd in thread_current for debugging purpose
  {
    return ;
  }
  
  lock_acquire(&filesys_lock);
  file_seek(fd_found->opened_file, position);
  lock_release(&filesys_lock);

}

unsigned 
tell (int fd)
{
  int position;
  struct file_desc * fd_found = get_file_desc (thread_current(), fd);
  if (fd_found == NULL) //No such fd in thread_current for debugging purpose
  {
    return -1;
  }

  lock_acquire(&filesys_lock);
  position = file_tell(fd_found->opened_file);
  lock_release(&filesys_lock);
  return position;

}

void 
close (int fd)
{
  struct file_desc * fd_found = get_file_desc (thread_current(), fd);
  if (fd_found == NULL) //No such fd in thread_current for debugging purpose
  {
    return ;
  }
  lock_acquire(&filesys_lock);
  file_close(fd_found->opened_file);  
  lock_release(&filesys_lock);
  // for programmer's perspective at given file.c and filesys.c etc, file_desc free is needed because its made by us.
  list_remove(&(fd_found->elem_f));
  free(fd_found);

}
