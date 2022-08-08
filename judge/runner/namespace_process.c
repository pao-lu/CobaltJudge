#define _GNU_SOURCE
#include "namespace_process.h"

#include <errno.h>   // for errno
#include <fcntl.h>   // for stat
#include <poll.h>    // for poll, pollfd, POLLIN
#include <sched.h>   // for clone, CLONE_PIDFD, CLONE_...
#include <signal.h>  // for kill, SIGKILL, SIGSYS, SIG...
#include <stdio.h>   // for perror, printf
#include <string.h>
#include <sys/mman.h>      // for MAP_FAILED, mmap, munmap
#include <sys/mount.h>     // for mount, MS_BIND, MS_NOSUID
#include <sys/random.h>    // for getrandom
#include <sys/resource.h>  // for prlimit, rlimit, RLIMIT_CORE
#include <sys/wait.h>      // for waitpid, WIFEXITED, WIFSIG...
#include <time.h>          // for timespec
#include <unistd.h>        // for close, sethostname

#include "cgroup_path.h"   // for CGROUP_MEMORY, CGROUP_CPUACCT
#include "share_fd.h"      // for namespace_process_recv_fd
#include "simple_futex.h"  // for sf_post, sf_wait
#include "user_process.h"  // for ns_user_share, USER_STACK_...
#include "util.h"          // for write_number, write_string

#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_DEV "/sandbox/dev"

#define PERR_AND_RETURN(label)     \
  do {                             \
    perror(label);                 \
    goto L_namespace_process_exit; \
  } while (0)

int namespace_process_function(struct main_ns_share *shared_addr) {
  struct stat stat_tmp;
  struct timespec spec;
  int mapfd;

  /* 1. 创建沙盒文件系统根目录 */

  try_makedir_f(SANDBOX_MOUNT);

  /* 2. 挂载沙盒文件系统 */
  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-fs-bind");
  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL,
            MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID, NULL) == -1)
    PERR_AND_RETURN("mount-fs-remount");

  if (mount(SANDBOX_DEV, SANDBOX_MOUNT "/dev", NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-dev-bind");

  if (mount("none", SANDBOX_MOUNT "/proc", "proc", 0, "") == -1)
    PERR_AND_RETURN("mount-proc");

  /* if (mount("/sys", SANDBOX_MOUNT "/sys", NULL, MS_BIND | MS_REC, NULL) ==
   * -1) */
  /*   PERR_AND_RETURN("mount-sys"); */

  /* 6. 设置主机名 */
  if (sethostname("sandbox", 7) == -1) PERR_AND_RETURN("sethostname");

  /* 初始化完成，通知主进程 */
  sf_post(&shared_addr->sf_ns_ready);

  for (; shared_addr->b_quit == false;) {
    sf_wait(&shared_addr->sf_main_ready);
    namespace_process_dojob(shared_addr);
    sf_post(&shared_addr->sf_ns_ready);
  }

  printf("%d namespace quit\n", shared_addr->namespace_id);
L_namespace_process_exit:
  kill(-1, SIGKILL);
  shared_addr->b_quit = 1;
  sf_post(&shared_addr->sf_ns_ready);
  return 0;
}

/* 由命名空间进程执行 */
void namespace_process_dojob(struct main_ns_share *main_share) {
  const int MAXNUM = 3;
  struct ns_user_share *shared_addr = (struct ns_user_share *)MAP_FAILED;
  struct job_desc *job = &main_share->j_desc;
  struct job_result *res = &main_share->j_res;
  struct pollfd fds;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid, w;
  struct itimerspec itimerspec;
  int wstatus;
  struct rlimit limit;
  intmax_t saved_int;
  int pidfd = -1;
  int fd[3] = {-1};
  /* execve之前的栈空间大小 */
  /* 5. 填写FD */
  memcpy(fd, job->fd, sizeof(fd));
  job->fd[0] = -1;
  res->init_result = 0;
  if (namespace_process_recv_fd(main_share->fd_sockets[1], job->fd) != 0) {
    res->init_result = IR_RECEIVE_FD;
    perror("recv fd");
    goto L_free_user_process;
  }

  /* 1. 挂载数据目录 */
  if (job->home_mount_dir[0] != '\0' &&
      mount(job->home_mount_dir, SANDBOX_MOUNT "/home", NULL,
            MS_BIND | MS_NOSUID, NULL) == -1) {
    res->init_result = IR_MOUNT_HOME;
    perror("do_job mount-data-dir");
    goto L_free_user_process;
  }

  /* 2. 分配共享空间 */
  /* 子进程在execve后不再保留此时mmap分配的内存*/
  shared_addr = (struct ns_user_share *)mmap(NULL, sizeof(*shared_addr),
                                             PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_addr == MAP_FAILED) {
    res->init_result = IR_MMAP_SHARED;
    perror("do_job mmap-shared_addr");
    goto L_free_user_process;
  }

  shared_addr->uid = NOBODY_UID;
  shared_addr->gid = NOBODY_GID;
  shared_addr->desc = job;

  shared_addr->sf_ns_ready = 0;
  shared_addr->sf_user_ready = 0;

  /* 3. 分配栈空间 */
  /* 只用于execve前的栈 */
  stack_addr = mmap(NULL, USER_STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack_addr == MAP_FAILED) {
    res->init_result = IR_MMAP_STACK;
    perror("do_job mmap-stack_addr");
    goto L_free_user_process;
  }

  /* 4. 禁止子进程执行execve、execveat */
  if (job->disable_execve) {
    if (getrandom(&shared_addr->cookie, sizeof(shared_addr->cookie), 0) == -1) {
      res->init_result = IR_DISABLE_EXECVE;
      perror("getrandom");
      goto L_free_user_process;
    }
  }
  /* 6. cgroup */
  if (write_number(0, CGROUP_CPUACCT "/sandbox-%X/sub/cpuacct.usage",
                   main_share->namespace_id) == -1) {
    res->init_result = IR_CGROUP;
    perror("cgroup clear cpuacct");
    goto L_free_user_process;
  }

  if (write_number(
          0, CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.max_usage_in_bytes",
          main_share->namespace_id) == -1) {
    res->init_result = IR_CGROUP;
    perror("cgroup clear memory usage");
    goto L_free_user_process;
  }

  if (write_string("-1\n", 3,
                   CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                   main_share->namespace_id) == -1) {
    res->init_result = IR_CGROUP;
    perror("cgroup memsw.limit reset");
    goto L_free_user_process;
  }

  if (job->memory_limit == 0) {
    if (write_string("-1\n", 3,
                     CGROUP_MEMORY "/sandbox-%X/sub/memory.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup memory_limit max");
      goto L_free_user_process;
    }
  } else {
    if (write_number(job->memory_limit + (1 << 20),
                     CGROUP_MEMORY "/sandbox-%X/sub/memory.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup memory_limit +1024");
      goto L_free_user_process;
    }
  }

  if (job->memory_limit == 0) {
    if (write_string("-1\n", 3,
                     CGROUP_MEMORY
                     "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup memsw.limit max");
      goto L_free_user_process;
    }
  } else {
    if (write_number(job->memory_limit + (1 << 20),
                     CGROUP_MEMORY
                     "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup memsw.limit +1024");
      goto L_free_user_process;
    }
  }

  if (job->pid_limit == 0) {
    if (write_string("max\n", 4, CGROUP_PIDS "/sandbox-%X/sub/pids.max",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup pid_limit");
      goto L_free_user_process;
    }
  } else {
    if (write_number(job->pid_limit, CGROUP_PIDS "/sandbox-%X/sub/pids.max",
                     main_share->namespace_id) == -1) {
      res->init_result = IR_CGROUP;
      perror("cgroup pid_limit");
      goto L_free_user_process;
    }
  }

  /* 7. 创建进程 */
  child_pid = clone(user_process_function, (char *)stack_addr + USER_STACK_SIZE,
                    CLONE_UNTRACED | CLONE_PIDFD, shared_addr, &pidfd);
  if (child_pid == -1) {
    res->init_result = IR_CLONE;
    goto L_free_user_process;
  }

  sf_wait(&shared_addr->sf_user_ready);

  /* 8. prlimit */
  if (job->output_limit != 0) {
    limit.rlim_cur = job->output_limit;
    limit.rlim_max = job->output_limit;
    if (prlimit(child_pid, RLIMIT_FSIZE, &limit, NULL) == -1) {
      res->init_result = IR_PRLIMIT;
      goto L_free_user_process;
    }
  }
  if (job->time_limit != 0) {
    limit.rlim_max = limit.rlim_cur = (job->time_limit + 999) / 1000 + 1;
    if (prlimit(child_pid, RLIMIT_CPU, &limit, NULL) == -1) {
      res->init_result = IR_PRLIMIT;
      goto L_free_user_process;
    }
  }
  limit.rlim_max = limit.rlim_cur = 0;
  if (prlimit(child_pid, RLIMIT_CORE, &limit, NULL) == -1) {
    res->init_result = IR_PRLIMIT;
    goto L_free_user_process;
  }
  limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
  if (prlimit(child_pid, RLIMIT_STACK, &limit, NULL) == -1) {
    res->init_result = IR_PRLIMIT;
    goto L_free_user_process;
  }

  /* 9. cgroup */

  if (write_number(child_pid, CGROUP_CPUACCT "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = IR_ENTER_CGROUP;
    goto L_free_user_process;
  }

  if (write_number(child_pid, CGROUP_MEMORY "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = IR_ENTER_CGROUP;
    goto L_free_user_process;
  }

  if (write_number(child_pid, CGROUP_PIDS "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = IR_ENTER_CGROUP;
    goto L_free_user_process;
  }

  sf_post(&shared_addr->sf_ns_ready);

  /* 10. wait result */

  fds.fd = pidfd;
  fds.events = POLLIN;
  wstatus = poll(&fds, 1, job->time_limit + 200);
  if (wstatus == -1) {
    res->init_result = IR_POLL;
    goto L_free_user_process;
  }
  if (wstatus == 0) {
    res->is_idle = true;
    kill(-1, SIGKILL);
  }

  do {
    w = waitpid(child_pid, &wstatus, WUNTRACED | WCONTINUED | __WALL);
    if (w == -1) {
      res->init_result = 10;
      goto L_free_user_process;
    }

    if (WIFEXITED(wstatus)) {
      res->is_killed = false;
      res->return_code = WEXITSTATUS(wstatus);
      /** printf("exited, status=%d\n", WEXITSTATUS(wstatus)); */
    } else if (WIFSIGNALED(wstatus)) {
      /** printf("killed by signal %d\n", WTERMSIG(wstatus)); */
      res->is_killed = true;
      res->kill_signal = WTERMSIG(wstatus);
      res->is_illegal = res->kill_signal == SIGSYS;
      res->is_ole = res->kill_signal == SIGXFSZ;
      /** } else if (WIFSTOPPED(wstatus)) { */
      /**     [> printf("stopped by signal %d\n", WSTOPSIG(wstatus)); <] */
      /**     kill(child_pid, SIGKILL); */
      /** } else if (WIFCONTINUED(wstatus)) { */
      /**     [> printf("continued\n"); <] */
      /**     kill(child_pid, SIGKILL); */
    } else {
      kill(-1, SIGKILL);
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  saved_int = read_int(CGROUP_CPUACCT "/sandbox-%X/sub/cpuacct.usage",
                       main_share->namespace_id);
  if (saved_int == -1) {
    res->time_used = -1;
    res->init_result = IR_RESULT;
    goto L_free_user_process;
  }
  res->time_used = (saved_int + 999999) / 1000000;
  res->is_tle = res->is_killed && (res->kill_signal == SIGXCPU) ||
                res->is_idle ||
                (job->time_limit != 0 && res->time_used > job->time_limit);

  saved_int =
      read_int(CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.max_usage_in_bytes",
               main_share->namespace_id);
  res->memory_used = saved_int;
  if (saved_int == -1) {
    res->init_result = IR_RESULT;
    goto L_free_user_process;
  }
  res->is_mle = job->memory_limit != 0 && res->memory_used > job->memory_limit;

  msync(main_share, sizeof(*main_share), MS_SYNC);

L_free_user_process:
  res->errsv = res->init_result ? errno : 0;
  if (fd[0] != -1) {
    close(fd[0]);
    close(fd[1]);
    close(fd[2]);
  }
  if (pidfd != -1) {
    close(pidfd);
  }
  if (shared_addr != MAP_FAILED) {
    munmap(shared_addr, sizeof(*shared_addr));
  }
  if (stack_addr != MAP_FAILED) {
    munmap(stack_addr, USER_STACK_SIZE);
  }
  kill(-1, SIGKILL);
}
