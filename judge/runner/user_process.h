#ifndef _USER_PROCESS_H_INCLUDED
#define _USER_PROCESS_H_INCLUDED

#include <stdint.h>     // for uint32_t
#include <sys/types.h>  // for gid_t, uid_t

#define USER_STACK_SIZE (32 * 1024)

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
  const struct job_desc *desc;
  uint32_t cookie;
  int status;
  int errsv;
  uint32_t sf_user_ready;
  uint32_t sf_ns_ready;
};

int user_process_function(void *arg);

#endif
