#define _GNU_SOURCE
#include <errno.h>       // for errno, ENOENT
#include <sched.h>       // for clone, CLONE_NEWCGROUP, CLO...
#include <signal.h>      // for kill, SIGKILL, SIGSYS
#include <stdint.h>      // for uint32_t, intmax_t
#include <stdio.h>       // for perror, printf, NULL, fprintf
#include <stdlib.h>      // for EXIT_FAILURE
#include <string.h>      // for strlen, strncpy
#include <sys/mman.h>    // for munmap, mmap, MAP_FAILED
#include <sys/mount.h>   // for mount, MS_BIND, MS_RDONLY
#include <sys/random.h>  // for getrandom
#include <sys/stat.h>    // for stat, mkdir
#include <sys/wait.h>    // for waitpid, WIFEXITED, WIFSIGN...
#include <syscall.h>     // for SYS_execve
#include <unistd.h>      // for getgid, getuid, syscall, pid_t

#include "simple_futex.h"  // for sf_post, sf_wait
#include "simple_jail.h"   // for go_simple_jail

#define DIR_MAX_LEN 256
#define errExit(msg)    \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

struct {
  uint32_t sf_father;
  uint32_t sf_child;
  uint32_t cookie;
  char new_dir[DIR_MAX_LEN];
  char *argv[2];
  char *envp[1];
} * shared_addr;

struct runner_args {
  const char *data_mount_dir;  //< mount to /home in sandbox
  int argc;
  const char **argv;  //< PWD = /home in sandbox
  const char **envp;

  struct {
    /**
     * IO for program
     * type
     * 0 = /dev/null
     * 1 = absolute path in sandbox
     * 2 = fd
     */
    int type;
    union {
      const char *path;
      int fd;
    };
  } input, output, error;

  // 0 = nolimit
  uint64_t time_limit, memory_limit, output_limit, error_limit;
};

static int child_func(void *arg) {
#define PERR_AND_RETURN(label)       \
  do {                               \
    perror(label);                   \
    sf_post(&shared_addr->sf_child); \
    goto L_child_cleanup;            \
  } while (0)

  int err;
  struct stat stat_tmp;

#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_DEV "/sandbox/dev"

  printf("[child] created\n");

  if (stat(SANDBOX_MOUNT, &stat_tmp) == -1) {
    if (errno == ENOENT) {
      if ((mkdir(SANDBOX_MOUNT, 0)) == -1) PERR_AND_RETURN("mkdir");
    } else {
      PERR_AND_RETURN("mount");
    }
  }

  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-fs-bind");
  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY,
            NULL) == -1)
    PERR_AND_RETURN("mount-fs-remount");

  if (mount(SANDBOX_DEV, SANDBOX_MOUNT "/dev", NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-dev-bind");

  if (mount("none", SANDBOX_MOUNT "/proc", "proc", 0, "") == -1)
    PERR_AND_RETURN("mount-proc");
  if (mount("/sys", SANDBOX_MOUNT "/sys", NULL, MS_BIND | MS_REC, NULL) == -1)
    PERR_AND_RETURN("mount-sys");

  sf_wait(&shared_addr->sf_father);
  if (go_simple_jail(shared_addr->cookie, 65534, 65534, SANDBOX_MOUNT) != 0) {
    sf_post(&shared_addr->sf_child);
    goto L_child_cleanup;
  }
  printf("[child] cookie: %x\n", shared_addr->cookie);
  sf_post(&shared_addr->sf_child);
  printf("[child] execve %s\n", shared_addr->new_dir);
  err = syscall(SYS_execve, shared_addr->new_dir, shared_addr->argv,
                shared_addr->envp, shared_addr->cookie);
  if (err != 0) {
    perror("[child] execve");
  }

L_child_cleanup:
  if (shared_addr != (void *)-1) munmap(shared_addr, sizeof(*shared_addr));
  return -1;
#undef PERR_AND_RETURN
}

int new_process(const char *dir) {
  pid_t child_pid, w;
  int err, wstatus;
  void *stack = MAP_FAILED;
  FILE *file;
  char tmp[256];

#define STACK_SIZE (32 * 1024)

  if (strlen(dir) >= DIR_MAX_LEN) {
    fprintf(stderr, "dir name too long\n");
    return -1;
  }

  shared_addr = mmap(NULL, sizeof(*shared_addr), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_addr == MAP_FAILED) {
    err = errno;
    perror("mmap for shared_addr");
    goto _cleanup2;
  }

  stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) {
    err = errno;
    perror("mmap for stack");
    goto _cleanup2;
  }

  shared_addr->argv[0] = shared_addr->new_dir;
  shared_addr->argv[1] = NULL;
  shared_addr->envp[0] = NULL;
  strncpy(shared_addr->new_dir, dir, DIR_MAX_LEN - 1);
  shared_addr->new_dir[DIR_MAX_LEN - 1] = 0;

  shared_addr->sf_father = 0;
  shared_addr->sf_child = 0;

  if (getrandom(&shared_addr->cookie, sizeof(shared_addr->cookie), 0) == -1) {
    err = errno;
    perror("getrandom");
    goto _cleanup2;
  }
  shared_addr->cookie &= 0x7fffffff;

  child_pid =
      clone(child_func, stack + STACK_SIZE,
            CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_UNTRACED,
            NULL);
  if (child_pid == -1) {
    // FAIL
    err = errno;
    perror("clone");
    goto _cleanup2;
  }

  printf("clone() returned %jd\n", (intmax_t)child_pid);

  // write uid map
  snprintf(tmp, 256, "/proc/%d/uid_map", child_pid);
  if ((file = fopen(tmp, "w")) == NULL) {
    err = errno;
    perror("open uid_map");
    kill(child_pid, SIGKILL);
    goto _cleanup2;
  }
  fprintf(file, "0 %d 1\n", getuid());
  fprintf(file, "65534 65534 1\n");
  if (fclose(file) != 0) {
    err = errno;
    perror("write uid_map");
    kill(child_pid, SIGKILL);
    goto _cleanup2;
  }

  // write gid map
  snprintf(tmp, 256, "/proc/%d/gid_map", child_pid);
  if ((file = fopen(tmp, "w")) == NULL) {
    err = errno;
    perror("open gid_map");
    kill(child_pid, SIGKILL);
    goto _cleanup2;
  }
  fprintf(file, "0 %d 1\n", getgid());
  fprintf(file, "65534 65534 1\n");
  if (fclose(file) != 0) {
    err = errno;
    perror("write gid_map");
    kill(child_pid, SIGKILL);
    goto _cleanup2;
  }

  sf_post(&shared_addr->sf_father);

  sf_wait(&shared_addr->sf_child);

  do {
    w = waitpid(child_pid, &wstatus, WUNTRACED | WCONTINUED | __WALL);
    if (w == -1) {
      perror("waitpid1");
      err = -2;
      break;
    }

    if (WIFEXITED(wstatus)) {
      printf("exited, status=%d\n", WEXITSTATUS(wstatus));
    } else if (WIFSIGNALED(wstatus)) {
      printf("killed by signal %d\n", WTERMSIG(wstatus));
      if (WTERMSIG(wstatus) == SIGSYS) {
        printf("illegal syscall\n");
      }
    } else if (WIFSTOPPED(wstatus)) {
      printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      kill(child_pid, SIGKILL);
    } else if (WIFCONTINUED(wstatus)) {
      printf("continued\n");
      kill(child_pid, SIGKILL);
    } else
      printf("wstatus: %x\n", wstatus);
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

_cleanup2:
  if (shared_addr != MAP_FAILED) munmap(shared_addr, sizeof(*shared_addr));

  if (stack != MAP_FAILED) munmap(stack, STACK_SIZE);

  return err;
}

int main() { return new_process("/bin/sh"); }
