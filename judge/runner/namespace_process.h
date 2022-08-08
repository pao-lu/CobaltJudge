#ifndef _NAMESPACE_PROCESS_H_INCLUDED
#define _NAMESPACE_PROCESS_H_INCLUDED

#include <stdbool.h>    // for bool
#include <stddef.h>     // for size_t
#include <stdint.h>     // for uint32_t
#include <sys/types.h>  // for gid_t, pid_t, uid_t

#include "job_desc.h"  // for job_desc, job_result

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

enum user_process_status {
  UPS_OK = 0,
  UPS_DUPFD = 1,
  UPS_CLOFD = 4,
  UPS_CLOTHERFD = 7,
  UPS_FAIL = 8,
  UPS_SECCOMP,
  UPS_EXECVE
};
struct ns_user_share {
  uid_t uid;
  gid_t gid;
  char *program;
  char **argv;
  char **envp;
  int fd[3];
  bool disable_execve;
  uint32_t cookie;
  int status;
  int errsv;
  uint32_t sf_user_ready;
  uint32_t sf_ns_ready;
};

int clone_namespace_process(uint32_t id, struct ns_proc_info *desc);
int free_namespace_process(struct ns_proc_info *info);

#endif
