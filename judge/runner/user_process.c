#define _GNU_SOURCE
#include "user_process.h"

#include <dirent.h>  // for dirent64, opendir, readdir64, DIR
#include <errno.h>   // for errno, EINTR
#include <grp.h>     // for setgroups
#include <malloc.h>
#include <stddef.h>     // for NULL
#include <stdint.h>     // for uint32_t
#include <stdio.h>      // for perror
#include <stdlib.h>     // for strtol
#include <sys/prctl.h>  // for prctl, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS
#include <syscall.h>    // for SYS_execve
#include <unistd.h>     // for chdir, close, chroot, dup2, getegid, geteuid

#include "seccomp.h"       // for set_seccomp
#include "simple_futex.h"  // for sf_post, sf_wait

#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_CGROUP "/sandbox-cgroup"
#define SANDBOX_DEV "/sandbox/dev"
#define STACK_SIZE (32 * 1024)
#define NOBODY_UID 65534
#define NOBODY_GID 65534

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

int user_process_function(void *arg) {
  struct ns_user_share *shared_addr = (struct ns_user_share *)arg;
  const struct job_desc *job = shared_addr->desc;
  char const **argv, **envp;
  size_t argvc, envpc;
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
    if (dup2(job->fd[i], i) == -1) {
      shared_addr->status = UPS_DUPFD + i;
      shared_addr->errsv = errno;
      return -1;
    }
    if (close(job->fd[i]) == -1) {
      shared_addr->status = UPS_CLOFD + i;
      shared_addr->errsv = errno;
      return -1;
    }
  }

  /* 6.3 限制execve */
  if (job->disable_execve) {
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

  /* 6.5 argc argv */
  argv = get_packed_args(job->argv);
  envp = get_packed_args(job->envp);

  puts("syscall");
  /* 执行命令 */
  syscall(SYS_execve, argv[0], argv, envp, shared_addr->cookie);

  /* 执行失败 */
  puts("fail");
  shared_addr->status = UPS_EXECVE;
  shared_addr->errsv = errno;
  free(envp);
  free(argv);
  return -1;
}
