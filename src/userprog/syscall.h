#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
#include <stdbool.h>
#endif /* userprog/syscall.h */

//typedef int pid_t;
bool decide_stack_growth_and_do_if_needed (void * esp, void * addr)
void halt (void);
void exit (int status);
int exec (const char *file);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

mapid_t mmap (int fd, void *addr);
void munmap (mapid_t);