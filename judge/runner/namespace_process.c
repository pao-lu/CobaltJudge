#define _GNU_SOURCE
#include "namespace_process.h"

#include <fcntl.h>   // for open, O_CLOEXEC, O_WRONLY
#include <sched.h>   // for clone, CLONE_UNTRACED
#include <signal.h>  // for kill, SIGKILL, SIGSYS, SIGXCPU
#include <stdio.h>   // for perror, printf
#include <string.h>
#include <sys/mman.h>      // for MAP_FAILED, mmap, munmap
#include <sys/mount.h>     // for mount, MS_BIND, MS_NOSUID
#include <sys/random.h>    // for getrandom
#include <sys/resource.h>  // for prlimit, rlimit, RLIMIT_CORE
#include <sys/wait.h>      // for waitpid, WIFEXITED, WIFSIGN...
#include <unistd.h>        // for close, write, sethostname

#include "cgroup_path.h"
#include "share_fd.h"      // for namespace_process_recv_fd
#include "simple_futex.h"  // for sf_post, sf_wait
#include "user_process.h"  // for ns_user_share, USER_STACK_SIZE
#include "util.h"          // for write_number, read_int, wri...

#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_DEV "/sandbox/dev"

#define PERR_AND_RETURN(label)     \
  do {                             \
    perror(label);                 \
    goto L_namespace_process_exit; \
  } while (0)

static void namespace_killall() { kill(-1, SIGKILL); }

int namespace_process_function(struct main_ns_share *shared_addr) {
  struct stat stat_tmp;
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
  namespace_killall();
  shared_addr->b_quit = 1;
  sf_post(&shared_addr->sf_ns_ready);
  return 0;
}

/* 由命名空间进程执行 */
void namespace_process_dojob(struct main_ns_share *main_share) {
  struct ns_user_share *shared_addr = (struct ns_user_share *)MAP_FAILED;
  struct job_desc *job = &main_share->j_desc;
  struct job_result *res = &main_share->j_res;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid, w;
  int wstatus;
  struct rlimit limit;
  intmax_t saved_int;
  /* execve之前的栈空间大小 */

  /* 1. 挂载数据目录 */
  if (job->home_mount_dir[0] != '\0' &&
      mount(job->home_mount_dir, SANDBOX_MOUNT "/home", NULL,
            MS_BIND | MS_NOSUID, NULL) == -1) {
    res->init_result = 1;
    perror("do_job mount-data-dir");
    return;
  }

  /* 2. 分配共享空间 */
  /* 子进程在execve后不再保留此时mmap分配的内存*/
  shared_addr = (struct ns_user_share *)mmap(NULL, sizeof(*shared_addr),
                                             PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_addr == MAP_FAILED) {
    res->init_result = 2;
    perror("do_job mmap-shared_addr");
    return;
  }
  // XXX
  shared_addr->uid = 65534;
  shared_addr->gid = 65534;
  shared_addr->desc = job;

  shared_addr->sf_ns_ready = 0;
  shared_addr->sf_user_ready = 0;

  /* 3. 分配栈空间 */
  /* 只用于execve前的栈 */
  stack_addr = mmap(NULL, USER_STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack_addr == MAP_FAILED) {
    res->init_result = 3;
    perror("do_job mmap-stack_addr");
    goto L_cannot_clone_user_process;
  }

  /* 4. 禁止子进程执行execve、execveat */
  if (job->disable_execve) {
    if (getrandom(&shared_addr->cookie, sizeof(shared_addr->cookie), 0) == -1) {
      res->init_result = 4;
      perror("getrandom");
      goto L_cannot_clone_user_process;
    }
  }

  /* 5. 填写FD */
  if (namespace_process_recv_fd(main_share->fd_socket_ns, job->fd) != 0) {
    res->init_result = 5;
    perror("recv fd");
    goto L_cannot_clone_user_process;
  }

  /* 6. cgroup */
  if (write_number(0, CGROUP_CPUACCT "/sandbox-%X/sub/cpuacct.usage",
                   main_share->namespace_id) == -1) {
    res->init_result = 6;
    perror("cgroup clear cpuacct");
    goto L_cannot_clone_user_process;
  }

  if (write_number(
          0, CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.max_usage_in_bytes",
          main_share->namespace_id) == -1) {
    res->init_result = 6;
    perror("cgroup clear memory usage");
    goto L_cannot_clone_user_process;
  }

  if (write_string("-1\n", 3,
                   CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                   main_share->namespace_id) == -1) {
    res->init_result = 6;
    perror("cgroup memsw.limit reset");
    goto L_cannot_clone_user_process;
  }

  if (job->memory_limit == 0) {
    if (write_string("-1\n", 3,
                     CGROUP_MEMORY "/sandbox-%X/sub/memory.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memory_limit max");
      goto L_cannot_clone_user_process;
    }
  } else {
    if (write_number(job->memory_limit + (1 << 20),
                     CGROUP_MEMORY "/sandbox-%X/sub/memory.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memory_limit +1024");
      goto L_cannot_clone_user_process;
    }
  }

  if (job->memory_limit == 0) {
    if (write_string("-1\n", 3,
                     CGROUP_MEMORY
                     "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memsw.limit max");
      goto L_cannot_clone_user_process;
    }
  } else {
    if (write_number(job->memory_limit + (1 << 20),
                     CGROUP_MEMORY
                     "/sandbox-%X/sub/memory.memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memsw.limit +1024");
      goto L_cannot_clone_user_process;
    }
  }

  if (job->pid_limit == 0) {
    if (write_string("max\n", 4, CGROUP_PIDS "/sandbox-%X/sub/pids.max",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup pid_limit");
      goto L_cannot_clone_user_process;
    }
  } else {
    if (write_number(job->pid_limit, CGROUP_PIDS "/sandbox-%X/sub/pids.max",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup pid_limit");
      goto L_cannot_clone_user_process;
    }
  }

  /* 7. 创建进程 */
  child_pid = clone(user_process_function, (char *)stack_addr + USER_STACK_SIZE,
                    CLONE_UNTRACED, shared_addr);
  if (child_pid == -1) {
    res->init_result = 7;
    perror("do_job clone");
    goto L_cannot_clone_user_process;
  }

  puts("sf_wait");
  sf_wait(&shared_addr->sf_user_ready);

  /* 8. prlimit */
  puts("prlimit");
  limit.rlim_cur = job->output_limit;
  limit.rlim_max = job->output_limit;
  if (prlimit(child_pid, RLIMIT_FSIZE, &limit, NULL) == -1) {
    res->init_result = 8;
    perror("do_job clone");
    goto L_cannot_clone_user_process;
  }
  limit.rlim_max = limit.rlim_cur = (job->time_limit + 999) / 1000 + 1;
  prlimit(child_pid, RLIMIT_CPU, &limit, NULL);
  limit.rlim_max = limit.rlim_cur = 0;
  prlimit(child_pid, RLIMIT_CORE, &limit, NULL);
  limit.rlim_max = limit.rlim_cur = RLIM_INFINITY;
  prlimit(child_pid, RLIMIT_STACK, &limit, NULL);

  /* 9. cgroup */

  puts("cgroup");
  if (write_number(child_pid, CGROUP_CPUACCT "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = 9;
    perror("cgroup enter cpuacct");
    goto L_cannot_clone_user_process;
  }

  if (write_number(child_pid, CGROUP_MEMORY "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = 9;
    perror("cgroup enter cpuacct");
    goto L_cannot_clone_user_process;
  }

  if (write_number(child_pid, CGROUP_PIDS "/sandbox-%X/sub/cgroup.procs",
                   main_share->namespace_id) == -1) {
    res->init_result = 9;
    perror("cgroup enter cpuacct");
    goto L_cannot_clone_user_process;
  }

  puts("post");
  sf_post(&shared_addr->sf_ns_ready);

  /* 10. wait result */
  puts("wait result");
  printf("ppid=%jd, pid=%jd\n", (intmax_t)getpid(), (intmax_t)child_pid);
  do {
    w = waitpid(child_pid, &wstatus, WUNTRACED | WCONTINUED | __WALL);
    if (w == -1) {
      perror("waitpid1");
      res->init_result = 10;
      break;
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
      printf("unknown wstatus: %x\n", wstatus);
      kill(child_pid, SIGKILL);
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  /* read_result */
  saved_int = read_int(CGROUP_CPUACCT "/sandbox-%X/sub/cpuacct.usage",
                       main_share->namespace_id);
  if (saved_int == -1) {
    res->time_used = -1;
    res->init_result = 11;
    goto L_cannot_clone_user_process;
  }
  res->time_used = (saved_int + 999999) / 1000000;
  res->is_tle = res->kill_signal == SIGXCPU ||
                (job->time_limit != 0 && res->time_used > job->time_limit);

  saved_int =
      read_int(CGROUP_MEMORY "/sandbox-%X/sub/memory.memsw.max_usage_in_bytes",
               main_share->namespace_id);
  res->memory_used = saved_int;
  if (saved_int == -1) {
    res->init_result = 11;
    goto L_cannot_clone_user_process;
  }
  res->is_mle = job->memory_limit != 0 && res->memory_used > job->memory_limit;

L_cannot_clone_user_process:
  if (shared_addr != MAP_FAILED) {
    munmap(shared_addr, sizeof(*shared_addr));
  }
  if (stack_addr != MAP_FAILED) {
    munmap(stack_addr, USER_STACK_SIZE);
  }
  namespace_killall();
}
