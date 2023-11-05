#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void 
check_address (const void *addr)
{
  if(addr >= PHYS_BASE || addr < (void*)(0x08048000) )
  {
    exit(-1);
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  check_address (f->esp);
  
  switch (*(uint32_t *) (f->esp)) // syscall number
  {
    case SYS_HALT:
    {
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      check_address (f->esp + 4);

      exit (*(int *)(f->esp + 4));
      break;
    }
    case SYS_EXEC:
    {
      check_address (f->esp + 4);

      f->eax = exec (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_WAIT:
    {
      check_address (f->esp + 4);

      f->eax = wait (*(int *)(f->esp + 4)); //pid_t == int
      break;
    }
    case SYS_CREATE:
    {
      check_address (f->esp + 4);
      check_address (f->esp + 8);

      f->eax = create (
          *(const char **)(f->esp + 4),
          *(unsigned *)(f->esp + 8)
          );
      break;
    }
    case SYS_REMOVE:
    {
      check_address (f->esp + 4);

      f->eax = remove (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_OPEN:
    {
      check_address (f->esp + 4);

      f->eax = open (*(const char **)(f->esp + 4));
      break;
    }
    case SYS_FILESIZE:
    {
      check_address (f->esp + 4);

      f->eax = filesize (*(int *)(f->esp + 4));
      break;
    }
    case SYS_READ:
    {
      check_address (f->esp + 4);
      check_address (f->esp + 8);
      check_address (f->esp + 12);

      f->eax = read (
          *(int *)(f->esp + 4),
          *(void **)(f->esp + 8) ,
          *(unsigned *)(f->esp + 12)
          );
      break;
    }
    case SYS_WRITE:
    {
      check_address (f->esp + 4);
      check_address (f->esp + 8);
      check_address (f->esp + 12);

      f->eax = write (
          *(int *)(f->esp + 4),
          *(const void **)(f->esp + 8),
          *(unsigned *)(f->esp + 12)
          );
      break;
    }
    case SYS_SEEK:
    {
      check_address (f->esp + 4);
      check_address (f->esp + 8);

      seek (
          *(int *)(f->esp + 4),
          *(unsigned *)(f->esp + 8)
          );
      break;
    }
    case SYS_TELL:
    {
      check_address (f->esp + 4);

      f->eax = tell (*(int *)(f->esp + 4));
      break;
    }
    case SYS_CLOSE:
    {
      check_address (f->esp + 4);

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
    if (cur_process->thread_info_p->tid == t->tid)
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
  
}

bool 
remove (const char *file)
{

}

int 
open (const char *file)
{

}

int 
filesize (int fd)
{

}

int 
read (int fd, void *buffer, unsigned length)
{

}

int 
write (int fd, const void *buffer, unsigned length)
{

}

void 
seek (int fd, unsigned position)
{

}

unsigned 
tell (int fd)
{

}

void 
close (int fd)
{

}
