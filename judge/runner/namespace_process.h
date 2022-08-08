#ifndef _NAMESPACE_PROCESS_H_INCLUDED
#define _NAMESPACE_PROCESS_H_INCLUDED

#include <stdbool.h>    // for bool
#include <stddef.h>     // for size_t
#include <stdint.h>     // for uint32_t
#include <sys/types.h>  // for gid_t, pid_t, uid_t

#include "job_desc.h"  // for job_desc, job_result

#define STACK_SIZE (32 * 1024)

struct main_ns_share {
  uint32_t sf_main_ready;
  uint32_t sf_ns_ready;
  bool b_quit;
  uint32_t namespace_id;
  int fd_socket_ns;
  struct job_desc j_desc;
  struct job_result j_res;
};

struct ns_proc_info {
  pid_t pid_ns_proc;
  int fd_socket_main;
  void *stack_addr;
  size_t stack_size;
  struct main_ns_share *shared_addr;
};

int namespace_process_function(struct main_ns_share *arg);
void namespace_process_dojob(struct main_ns_share *main_share);

#endif
