#define _GNU_SOURCE
#include "namespace_process.h"

#include <dirent.h>
#include <errno.h>  // for errno, ENOENT
#include <fcntl.h>  // for open, O_CLOEXEC, O_WRONLY
#include <grp.h>    // for setgroups
#include <sched.h>  // for clone, CLONE_UNTRACED, CLON...
#include <signal.h>
#include <stdint.h>  // for uint32_t, intmax_t
#include <stdio.h>   // for perror, NULL, fprintf, printf
#include <stdlib.h>
#include <string.h>      // for memcpy, memset
#include <sys/mman.h>    // for munmap, MAP_FAILED, mmap
#include <sys/mount.h>   // for mount, MS_BIND, MS_RDONLY
#include <sys/prctl.h>   // for prctl, PR_SET_DUMPABLE, PR_...
#include <sys/random.h>  // for getrandom
#include <sys/resource.h>
#include <sys/stat.h>  // for stat, mkdir
#include <sys/time.h>
#include <sys/types.h>  // for pid_t
#include <sys/wait.h>
#include <syscall.h>  // for SYS_execve
#include <unistd.h>   // for close, chdir, write, chroot

#include "seccomp.h"  // for set_seccomp
#include "share_fd.h"
#include "simple_futex.h"  // for sf_post, sf_wait

#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_CGROUP "/sandbox-cgroup"
#define SANDBOX_DEV "/sandbox/dev"
#define STACK_SIZE (32 * 1024)
#define USER_STACK_SIZE (32 * 1024)
#define NOBODY_UID 65534
#define NOBODY_GID 65534

#define CGROUP_CPUACCT "/sys/fs/cgroup/cpuacct"
#define CGROUP_MEMORY "/sys/fs/cgroup/memory"
#define CGROUP_PIDS "/sys/fs/cgroup/pids"

static const char map_content[] = "0 0 1\n65534 65534 1\n";

static int namespace_process_function(void *arg);
static int user_process_function(void *arg);

static int try_makedir(const char *dir) {
  struct stat stat_tmp;
  if (stat(dir, &stat_tmp) == -1) {
    if (errno == ENOENT) {
      if (mkdir(dir, 0) == -1) {
        return -1;
      } else {
        return 0;
      }
    } else {
      return -1;
    }
  }
  return 0;
}

static int try_makedir_f(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  return try_makedir(tmp);
}

static int rmdir_f(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  return rmdir(tmp);
}

static int write_number(uintmax_t num, const char *dir, ...) {
  va_list ap;
  char tmp[256];
  int len;
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  int fd = open(dir, O_WRONLY | O_CLOEXEC | O_SYNC);
  if (fd == -1) {
    return -1;
  }
  len = snprintf(tmp, 256, "%ju\n", num);
  if (write(fd, tmp, len) == -1) {
    return -1;
  }
  if (close(fd) == -1) {
    return -1;
  }

  return 0;
}

static int write_string(const char *str, int len, const char *dir, ...) {
  va_list ap;
  char tmp[256];
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  int fd = open(dir, O_WRONLY | O_CLOEXEC | O_SYNC);
  if (fd == -1) {
    return -1;
  }
  if (write(fd, str, len) == -1) {
    return -1;
  }
  if (close(fd) == -1) {
    return -1;
  }

  return 0;
}

static intmax_t read_int(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  intmax_t res;

  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  FILE *file = fopen(tmp, "r");
  if (fscanf(file, "%jd", &res) != 1) {
    res = -1;
  }
  fclose(file);

  return res;
}

/* 由主进程执行 */
int clone_namespace_process(uint32_t id, struct ns_proc_info *desc) {
  struct main_ns_share *shared_addr = MAP_FAILED;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid;

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
    return -1;
  }

  memset(shared_addr, 0, sizeof(*shared_addr));
  shared_addr->namespace_id = id;

  stack_addr = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack_addr == MAP_FAILED) {
    perror("mmap for stack");
    goto L_cannot_clone_namespace_process;
  }

  child_pid =
      clone(namespace_process_function, (char *)stack_addr + STACK_SIZE,
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

  sf_post(&shared_addr->sf_main_ready);

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
  return 0;
}

int free_namespace_process(struct ns_proc_info *info) {
  kill(info->pid_ns_proc, SIGKILL);
  waitpid(info->pid_ns_proc, NULL, __WALL);
  close(info->fd_socket_main);
  rmdir_f(CGROUP_PIDS "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_PIDS "/sandbox-%X", info->pid_ns_proc);
  rmdir_f(CGROUP_MEMORY "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_MEMORY "/sandbox-%X", info->pid_ns_proc);
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X/sub", info->pid_ns_proc);
  rmdir_f(CGROUP_CPUACCT "/sandbox-%X", info->pid_ns_proc);
  munmap(info->stack_addr, sizeof(*info->stack_addr));
  munmap(info->shared_addr, sizeof(*info->shared_addr));
  return 0;
}

/****************************************************************/

#define PERR_AND_RETURN(label)     \
  do {                             \
    perror(label);                 \
    goto L_namespace_process_exit; \
  } while (0)

static void namespace_killall() {
  kill(-1, SIGKILL);
  while (waitpid(-1, NULL, __WALL) != -1)
    ;
}

static int namespace_process_function(void *arg) {
  struct main_ns_share *shared_addr = (struct main_ns_share *)arg;
  struct stat stat_tmp;
  int mapfd;

  /* 1. 创建沙盒文件系统根目录 */

#define TRY_MKDIR(dir)                                                    \
  if (stat(dir, &stat_tmp) == -1) {                                       \
    if (errno == ENOENT) {                                                \
      if ((mkdir(SANDBOX_MOUNT, 0)) == -1) PERR_AND_RETURN("mkdir " dir); \
    } else {                                                              \
      PERR_AND_RETURN("stat " dir);                                       \
    }                                                                     \
  }
  TRY_MKDIR(SANDBOX_MOUNT);

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

  /* 7. 填写uid_map gid_map */
  if ((mapfd = open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC)) == -1)
    PERR_AND_RETURN("open uid_map");
  if (write(mapfd, map_content, sizeof(map_content) - 1) == -1)
    PERR_AND_RETURN("write uid_map");
  if (close(mapfd) == -1) PERR_AND_RETURN("close uid_map");

  if ((mapfd = open("/proc/self/gid_map", O_WRONLY | O_CLOEXEC)) == -1)
    PERR_AND_RETURN("open gid_map");
  if (write(mapfd, map_content, sizeof(map_content) - 1) == -1)
    PERR_AND_RETURN("write gid_map");
  if (close(mapfd) == -1) PERR_AND_RETURN("close gid_map");

  /* 初始化完成，通知主进程 */
  sf_post(&shared_addr->sf_ns_ready);
  sf_wait(&shared_addr->sf_main_ready);

  for (int i = 0; i < 1000; i++) {
    /* 随便写 */
    shared_addr->j_desc.argc ^= i;
  }
  printf("done\n");
L_namespace_process_exit:
  namespace_killall();
  shared_addr->b_quit = 1;
  sf_post(&shared_addr->sf_ns_ready);
  return 0;
}

/* 由命名空间进程执行 */
static void namespace_process_dojob(const struct main_ns_share *main_share,
                                    const struct job_desc *job,
                                    struct job_result *res) {
  struct ns_user_share *shared_addr = MAP_FAILED;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid, w;
  int wstatus;
  struct rlimit limit;
  intmax_t saved_int;
  /* execve之前的栈空间大小 */

  /* 1. 挂载数据目录 */
  if (job->data_mount_dir != NULL &&
      mount(job->data_mount_dir, SANDBOX_MOUNT "/home", NULL,
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
  shared_addr->disable_execve = job->disable_execve;
  if (job->disable_execve) {
    if (getrandom(&shared_addr->cookie, sizeof(shared_addr->cookie), 0) == -1) {
      res->init_result = 4;
      perror("getrandom");
      goto L_cannot_clone_user_process;
    }
  }

  /* 5. 填写FD */
  if (namespace_process_recv_fd(main_share->fd_socket_ns, shared_addr->fd) !=
      0) {
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

  if (job->memory_limit == 0) {
    if (write_string("-1\n", 3,
                     CGROUP_MEMORY "/sandbox-%X/sub/memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memory_limit");
      goto L_cannot_clone_user_process;
    }
  } else {
    if (write_number(job->memory_limit + 1024,
                     CGROUP_MEMORY "/sandbox-%X/sub/memsw.limit_in_bytes",
                     main_share->namespace_id) == -1) {
      res->init_result = 6;
      perror("cgroup memory_limit");
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
    if (write_number(job->pid_limit, CGROUP_MEMORY "/sandbox-%X/sub/pids.max",
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

  sf_wait(&shared_addr->sf_user_ready);

  /* 8. prlimit */
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

  sf_post(&shared_addr->sf_ns_ready);

  /* 10. wait result */
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
    res->init_result = 11;
    goto L_cannot_clone_user_process;
  }
  res->time_used = (saved_int + 999999) / 1000000;
  res->is_tle = res->kill_signal == SIGXCPU ||
                (job->time_limit != 0 && res->time_used > job->time_limit);

  saved_int = read_int(CGROUP_CPUACCT "/sandbox-%X/sub/memory.usage",
                       main_share->namespace_id);
  if (saved_int == -1) {
    res->init_result = 11;
    goto L_cannot_clone_user_process;
  } else {
    res->memory_used = saved_int;
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

static int restartable_close(int fd) {
  int errsv = 0;
  do {
    if (close(fd) == 0) break;
    errsv = errno;
  } while (errsv == EINTR);
  return errsv;
}

static int user_process_close_fd() {
  DIR *dir;
  struct dirent64 *dirent;
  int fd;

  restartable_close(4);
  restartable_close(5);

  dir = opendir("/proc/self/fd");
  if (dir == NULL) {
    return -2;
  }

  while ((dirent = readdir64(dir)) != NULL) {
    if (dirent->d_name[0] >= '0' && dirent->d_name[0] <= '9' &&
        (fd = strtol(dirent->d_name, NULL, 10)) > 5) {
      if (restartable_close(fd) != 0) {
        return -3;
      }
    }
  }

  return 0;
}

static int user_process_function(void *arg) {
  struct ns_user_share *shared_addr = (struct ns_user_share *)arg;
  uint32_t cookie;
#undef PERR_AND_RETURN
#define PERR_AND_RETURN(label)      \
  do {                              \
    shared_addr->status = UPS_FAIL; \
    shared_addr->errsv = errno;     \
    perror(label);                  \
    return -1;                      \
  } while (0)
  /* 6.1 降低权限 */
  if (prctl(PR_SET_DUMPABLE, 0) == -1) PERR_AND_RETURN("set_dumpable");
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
    PERR_AND_RETURN("no_new_privs");
  if (chdir(SANDBOX_MOUNT) == -1) PERR_AND_RETURN("chdir");
  if (chroot(".") == -1) PERR_AND_RETURN("chroot .");
  if (chdir("/") == -1) PERR_AND_RETURN("chdir /");

  if (setgid(shared_addr->gid) == -1) PERR_AND_RETURN("setgid");
  if (setgroups(1, &shared_addr->gid) == -1) PERR_AND_RETURN("setgroups");

  if (setuid(shared_addr->uid) == -1) PERR_AND_RETURN("setuid");
  if (setsid() == -1) PERR_AND_RETURN("setsid");
  if (getuid() != shared_addr->uid || geteuid() != shared_addr->uid ||
      getgid() != shared_addr->gid || getegid() != shared_addr->gid) {
    PERR_AND_RETURN("deroot failed");
  }
  /* 6.2 设置FD */
  for (int i = 0; i < 3; i++) {
    if (dup2(shared_addr->fd[i], i) == -1) {
      shared_addr->status = UPS_DUPFD + i;
      shared_addr->errsv = errno;
      return -1;
    }
    if (close(shared_addr->fd[i]) == -1) {
      shared_addr->status = UPS_CLOFD + i;
      shared_addr->errsv = errno;
      return -1;
    }
  }

  /* 6.3 限制execve */
  if (shared_addr->disable_execve) {
    if (set_seccomp(shared_addr->cookie) == -1) {
      shared_addr->status = UPS_SECCOMP;
      shared_addr->errsv = errno;
      return -1;
    }
  }

  if (user_process_close_fd() != 0) {
    shared_addr->status = UPS_CLOTHERFD;
    shared_addr->errsv = errno;
    return -1;
  }

  sf_post(&shared_addr->sf_user_ready);
  /* 6.4 等待主进程设置限制 */
  sf_wait(&shared_addr->sf_ns_ready);

  /* 执行命令 */
  syscall(SYS_execve, shared_addr->program, shared_addr->argv,
          shared_addr->envp, shared_addr->cookie);

  /* 执行失败 */
  shared_addr->status = UPS_EXECVE;
  shared_addr->errsv = errno;
  return -1;
}
