#ifndef _JOB_DESC_H_INCLUDED
#define _JOB_DESC_H_INCLUDED
#include <stdbool.h>
#include <stdint.h>

struct job_desc {
  const char *data_mount_dir;  //< 挂载到沙盒中的/home目录
  int argc;
  const char **argv;  //< PWD = 沙盒中的/home
  const char **envp;

  int fd[3];

  // 0 = 无限制
  uint64_t time_limit, memory_limit, output_limit, pid_limit;
  bool disable_execve;
};

struct job_result {
  int init_result;
  uint64_t time_used, memory_used;
  bool is_tle, is_mle, is_ole, is_illegal;
  bool is_killed;
  union {
    int return_code;
    int kill_signal;
  };
};

#endif
