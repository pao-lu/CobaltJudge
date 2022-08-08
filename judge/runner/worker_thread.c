#define _GNU_SOURCE
#include <sched.h>     // for clone, CLONE_NEWCGROUP, CLO...
#include <signal.h>    // for kill, SIGKILL
#include <stdint.h>    // for intmax_t, uint32_t
#include <stdio.h>     // for perror, fprintf, NULL, printf
#include <string.h>    // for memset
#include <sys/mman.h>  // for munmap, MAP_FAILED, mmap
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>  // for waitpid, __WALL
#include <unistd.h>    // for close, pid_t

#include "cgroup_path.h"
#include "namespace_process.h"  // for ns_proc_info, main_ns_share
#include "share_fd.h"
#include "simple_futex.h"  // for sf_post, sf_wait
#include "util.h"          // for rmdir_f, try_makedir_f, wri...

static const char map_content[] = "0 0 1\n65534 65534 1\n";

/* 由主进程执行 */
int clone_namespace_process(uint32_t id, struct ns_proc_info *desc) {
  struct main_ns_share *shared_addr = (struct main_ns_share *)MAP_FAILED;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid;
  int sockets[2] = {-1, -1};

  if (try_makedir_f(CGROUP_CPUACCT "/sandbox-%X", id) == -1) {
    perror("cpuacct");
    goto L_cannot_create_cpuacct;
  }
  if (try_makedir_f(CGROUP_MEMORY "/sandbox-%X", id) == -1) {
    perror("memory");
    goto L_cannot_create_memory;
  }
  if (try_makedir_f(CGROUP_PIDS "/sandbox-%X", id) == -1) {
    perror("pids");
    goto L_cannot_create_pids;
  }
  if (try_makedir_f(CGROUP_CPUACCT "/sandbox-%X/sub", id) == -1) {
    perror("cpuacct");
    goto L_cannot_create_cpuacct;
  }
  if (try_makedir_f(CGROUP_MEMORY "/sandbox-%X/sub", id) == -1) {
    perror("memory");
    goto L_cannot_create_memory;
  }
  if (try_makedir_f(CGROUP_PIDS "/sandbox-%X/sub", id) == -1) {
    perror("pids");
    goto L_cannot_create_pids;
  }

  shared_addr = (struct main_ns_share *)mmap(NULL, sizeof(*shared_addr),
                                             PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (shared_addr == MAP_FAILED) {
    perror("mmap for shared_addr");
    goto L_cannot_clone_namespace_process;
  }

  memset(shared_addr, 0, sizeof(*shared_addr));

  shared_addr->namespace_id = id;

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1) {
    perror("socketpair");
    goto L_cannot_clone_namespace_process;
  }

  printf("socket: %d %d\n", sockets[0], sockets[1]);

  shared_addr->fd_sockets[0] = sockets[0];
  shared_addr->fd_sockets[1] = sockets[1];

  stack_addr = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack_addr == MAP_FAILED) {
    perror("mmap for stack");
    goto L_cannot_clone_namespace_process;
  }

  child_pid =
      clone((int (*)(void *))namespace_process_function,
            (char *)stack_addr + STACK_SIZE,
            CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_UNTRACED,
            shared_addr);
  if (child_pid == -1) {
    perror("clone");
    goto L_cannot_clone_namespace_process;
  }

  printf("%s: ns_pid = %jd\n", __func__, (intmax_t)child_pid);

  if (write_number(child_pid, CGROUP_CPUACCT "/sandbox-%X/cgroup.procs", id) ==
      -1) {
    perror("writepid cgroup_acct");
    goto L_kill_namespace_process;
  }
  if (write_number(child_pid, CGROUP_MEMORY "/sandbox-%X/cgroup.procs", id) ==
      -1) {
    perror("writepid cgroup_memory");
    goto L_kill_namespace_process;
  }
  if (write_number(child_pid, CGROUP_PIDS "/sandbox-%X/cgroup.procs", id) ==
      -1) {
    perror("writepid cgroup_pids");
    goto L_kill_namespace_process;
  }

  if (write_string(map_content, sizeof(map_content), "/proc/%jd/uid_map",
                   child_pid) == -1) {
    perror("write uid_map");
    goto L_kill_namespace_process;
  }
  if (write_string(map_content, sizeof(map_content), "/proc/%jd/gid_map",
                   child_pid) == -1) {
    perror("write gid_map");
    goto L_kill_namespace_process;
  }

  /* 等待子进程初始化 */

  sf_wait(&shared_addr->sf_ns_ready);

  if (shared_addr->b_quit) {
    fprintf(stderr, "%s: initialize failed\n", __func__);
    goto L_cannot_clone_namespace_process;
  }

  desc->pid_ns_proc = child_pid;
  desc->stack_addr = stack_addr;
  desc->stack_size = STACK_SIZE;
  desc->shared_addr = shared_addr;

  return 0;
L_kill_namespace_process:
  kill(child_pid, SIGKILL);
  waitpid(child_pid, NULL, __WALL);
L_cannot_clone_namespace_process:
  rmdir_f(CGROUP_PIDS "/sandbox-%X/sub", id);
  rmdir_f(CGROUP_PIDS "/sandbox-%X", id);
L_cannot_create_pids:
  rmdir_f(CGROUP_MEMORY "/sandbox-%X/sub", id);
  rmdir_f(CGROUP_MEMORY "/sandbox-%X", id);
L_cannot_create_memory:
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X/sub", id);
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X", id);
L_cannot_create_cpuacct:
  fprintf(stderr, "%s: can not clone\n", __func__);
  if (shared_addr != MAP_FAILED) {
    munmap(shared_addr, sizeof(*shared_addr));
  }
  if (stack_addr != MAP_FAILED) {
    munmap(stack_addr, STACK_SIZE);
  }
  if (sockets[0] != -1) {
    close(sockets[0]);
    close(sockets[1]);
  }
  return -1;
}

int free_namespace_process(struct ns_proc_info *info) {
  kill(info->pid_ns_proc, SIGKILL);
  waitpid(info->pid_ns_proc, NULL, __WALL);
  if (info->shared_addr->fd_sockets[1] != -1) {
    close(info->shared_addr->fd_sockets[0]);
    close(info->shared_addr->fd_sockets[1]);
  }
  rmdir_f(CGROUP_PIDS "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_PIDS "/sandbox-%X", info->pid_ns_proc);
  rmdir_f(CGROUP_MEMORY "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_MEMORY "/sandbox-%X", info->pid_ns_proc);
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X", info->pid_ns_proc);
  munmap(info->stack_addr, STACK_SIZE);
  munmap(info->shared_addr, sizeof(*info->shared_addr));
  return 0;
}

int send_job(struct ns_proc_info *info, struct job_desc *desc) {
  struct main_ns_share *shared_addr = info->shared_addr;
  if (shared_addr->b_quit) {
    return -1;
  }
  shared_addr->b_quit = false;
  memset(&shared_addr->j_res, 0, sizeof(shared_addr->j_res));
  memcpy(&shared_addr->j_desc, desc, sizeof(*desc));
  if (worker_send_fd(shared_addr->fd_sockets[0], desc->fd) == -1) {
    return -1;
  }
  sf_post(&shared_addr->sf_main_ready);
  return 0;
}
