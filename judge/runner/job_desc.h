#ifndef _JOB_DESC_H_INCLUDED
#define _JOB_DESC_H_INCLUDED
struct job_desc {
  const char *data_mount_dir;  //< 挂载到沙盒中的/home目录
  int argc;
  const char **argv;  //< PWD = 沙盒中的/home
  const char **envp;

  struct {
    /**
     * 程序IO说明
     * 0 = /dev/null
     * 1 = 沙盒中的绝对路径
     * 2 = fd
     */
    int type;
    union {
      const char *path;
      int fd;
    };
  } input, output, error;

  // 0 = 无限制
  uint64_t time_limit, memory_limit, output_limit, error_limit;
};
#endif
