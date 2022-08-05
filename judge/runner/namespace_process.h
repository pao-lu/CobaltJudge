#ifndef _NAMESPACE_PROCESS_H_INCLUDED
#define _NAMESPACE_PROCESS_H_INCLUDED

#include <stdint.h>
#include <unistd.h>  // for pid_t

#include "job_desc.h"

struct main_ns_share {
  uint32_t sf_ns_ready;
  uint32_t sf_main_ready;
  unsigned char b_quit;
  struct job_desc j_desc;
};

struct ns_proc_info {
  pid_t pid_ns_proc;
  void *stack_addr;
  size_t stack_size;
  struct main_ns_share *shared_addr;
};

int clone_namespace_process(struct ns_proc_info *desc);
int free_namespace_process(struct ns_proc_info *info);

#endif
