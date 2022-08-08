/**
 * +------------------------------+
 * |            主进程            |
 * |                              |
 * | +--------+--------+--------+ |
 * | |工作线程|        |        | |
 * | |        |        |        | |
 * +-+--+--^--+--------+--------+-+
 *      |  |  UNIX socket pair
 * +----v--+----+  uid=0 gid=0 CLONE_FILES
 * |命名空间进程|  cgroup_ns ipc_ns net_ns mount_ns
 * +----+-------+  pid_ns user_ns uts_ns
 *      |
 * +----v-------+
 * |用户程序进程|  uid=nobody gid=nobody
 * +------------+
 **/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "namespace_process.h"
#include "simple_futex.h"
#include "worker_thread.h"

char const *argv[] = {"/bin/gcc", "-v", NULL};
char const *envp[] = {NULL};

int main() {
  printf("main%jd\n", (intmax_t)getpid());
  struct ns_proc_info info;
  if (clone_namespace_process(0x1234, &info) != 0) {
    printf("can not clone\n");
    return -1;
  }

  puts("initialized");

  struct job_desc desc;
  memset(&desc, 0, sizeof(desc));
  strcpy(desc.home_mount_dir, "/dev/shm/test");
  job_desc_add_argv(&desc, "/usr/bin/gcc");
  job_desc_add_argv(&desc, "/home/test.c");
  job_desc_add_argv(&desc, "-o");
  job_desc_add_argv(&desc, "/home/good");
  job_desc_add_envp(&desc, "TMPDIR=/home/tmp");
  desc.fd[0] = 0;
  desc.fd[1] = 1;
  desc.fd[2] = 2;
  desc.disable_execve = false;
  desc.time_limit = 1000;
  desc.memory_limit = 128 << 20;
  desc.output_limit = 1024 * 1024 * 16;
  desc.pid_limit = 10;

  send_job(&info, &desc);

  sf_wait(&info.shared_addr->sf_ns_ready);

  print_job_res(&info.shared_addr->j_res);

  free_namespace_process(&info);
  return 0;
}
