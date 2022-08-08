#ifndef _JOB_DESC_H_INCLUDED
#define _JOB_DESC_H_INCLUDED
#include <stdbool.h>
#include <stdint.h>

struct job_desc {
  /* 空字符串表示不挂载/home */
  char home_mount_dir[256];
  /* 用NULL分割，2NULL结束 */
  char argv[1024];
  /* 用NULL分割，2NULL结束 */
  char envp[1024];
  union {
    int fd[3];
    int pointer[2];
  };
  bool disable_execve;
  // 0 = 无限制
  uint64_t time_limit, memory_limit, output_limit, pid_limit;
};

enum init_result {
  IR_SUCCESS,
  IR_MOUNT_HOME = 1,
  IR_MMAP_SHARED,
  IR_MMAP_STACK,
  IR_DISABLE_EXECVE,
  IR_RECEIVE_FD,
  IR_CGROUP,
  IR_CLONE,
  IR_PRLIMIT,
  IR_ENTER_CGROUP,
  IR_POLL,
  IR_RESULT

};

struct job_result {
  int init_result;
  uint64_t time_used, memory_used;
  bool is_tle, is_mle, is_ole, is_illegal, is_idle;
  bool is_killed;
  union {
    int return_code;
    int kill_signal;
  };
  int errsv;
};

void print_job_res(const struct job_result *res);
int job_desc_add(char *buf, int *pointer, const char *str);
const char **get_packed_args(const char *buf);

/** 在填写fd前使用 */
#define job_desc_add_argv(desc, str) \
  job_desc_add((desc)->argv, &(desc)->pointer[0], str)

/** 在填写fd前使用 */
#define job_desc_add_envp(desc, str) \
  job_desc_add((desc)->envp, &(desc)->pointer[1], str)

/** 在获取fd后并清空pointer后使用 */
#define job_desc_get_argv(desc) job_desc_get((desc)->argv, &(desc)->pointer[0])

/** 在获取fd后并清空pointer后使用 */
#define job_desc_get_envp(desc) job_desc_get((desc)->envp, &(desc)->pointer[1])

#endif
