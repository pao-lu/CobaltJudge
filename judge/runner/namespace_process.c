#define _GNU_SOURCE
#include "namespace_process.h"

#include <errno.h>     // for ENOENT, errno
#include <sched.h>     // for clone, CLONE_FILES, CLONE_N...
#include <stdint.h>    // for intmax_t
#include <stdio.h>     // for perror, fprintf, printf, NULL
#include <string.h>    // for memset
#include <sys/mman.h>  // for mmap, MAP_FAILED, munmap
#include <sys/mount.h>
#include <sys/stat.h>  // for stat, mkdir

#include "simple_futex.h"  // for sf_wait

static int namespace_process_function(void *arg);

/* 由主进程执行 */
int clone_namespace_process(struct ns_proc_info *desc) {
  struct main_ns_share *shared_addr = MAP_FAILED;
  void *stack_addr = MAP_FAILED;
  pid_t child_pid;
#define STACK_SIZE (32 * 1024)

  shared_addr = (struct main_ns_share *)mmap(NULL, sizeof(*shared_addr),
                                             PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (shared_addr == MAP_FAILED) {
    perror("mmap for shared_addr");
    return -1;
  }

  memset(shared_addr, 0, sizeof(*shared_addr));

  stack_addr = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack_addr == MAP_FAILED) {
    perror("mmap for stack");
    goto L_cannot_clone_namespace_process;
  }

  child_pid = clone(namespace_process_function, (char *)stack_addr + STACK_SIZE,
                    CLONE_FILES | CLONE_NEWCGROUP | CLONE_NEWIPC |
                        CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |
                        CLONE_NEWUSER | CLONE_NEWUTS | CLONE_UNTRACED,
                    shared_addr);
  if (child_pid == -1) {
    perror("clone");
    goto L_cannot_clone_namespace_process;
  }

  printf("%s: ns_pid = %jd\n", __func__, (intmax_t)child_pid);

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

  return 0;

L_cannot_clone_namespace_process:
  fprintf(stderr, "%s: can not clone\n", __func__);
  if (shared_addr != MAP_FAILED) {
    munmap(shared_addr, sizeof(*shared_addr));
  }
  if (stack_addr != MAP_FAILED) {
    munmap(stack_addr, STACK_SIZE);
  }
  return -1;
}

int free_namespace_process(struct ns_proc_info *info) {
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

static int namespace_process_function(void *arg) {
  struct main_ns_share *shared_addr = (struct main_ns_share *)arg;
  struct stat stat_tmp;

  /* 1. 创建沙盒文件系统根目录 */
#define SANDBOX_FS "/sandbox/fs"
#define SANDBOX_MOUNT "/sandbox-mount"
#define SANDBOX_DEV "/sandbox/dev"

  if (stat(SANDBOX_MOUNT, &stat_tmp) == -1) {
    if (errno == ENOENT) {
      if ((mkdir(SANDBOX_MOUNT, 0)) == -1) PERR_AND_RETURN("mkdir");
    } else {
      PERR_AND_RETURN("mount");
    }
  }

  /* 2. 挂载沙盒文件系统根目录 */
  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-fs-bind");
  if (mount(SANDBOX_FS, SANDBOX_MOUNT, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY,
            NULL) == -1)
    PERR_AND_RETURN("mount-fs-remount");

  /* 3. 挂载/dev */
  if (mount(SANDBOX_DEV, SANDBOX_MOUNT "/dev", NULL, MS_BIND, NULL) == -1)
    PERR_AND_RETURN("mount-dev-bind");

  /* 4. 挂载/proc */
  if (mount("none", SANDBOX_MOUNT "/proc", "proc", 0, "") == -1)
    PERR_AND_RETURN("mount-proc");

  /* 5. 挂载/sys */
  if (mount("/sys", SANDBOX_MOUNT "/sys", NULL, MS_BIND | MS_REC, NULL) == -1)
    PERR_AND_RETURN("mount-sys");

  /* 6. 设置主机名 */
  if (sethostname("sandbox", 7) == -1) PERR_AND_RETURN("sethostname");

  /* 初始化完成，通知主进程 */
  sf_post(&shared_addr->sf_ns_ready);
  sf_wait(&shared_addr->sf_main_ready);

  for (int i = 0; i < 1000; i++) {
    /* 随便写 */
    shared_addr->j_desc.argc ^= i;
  }
  printf("done\n");
L_namespace_process_exit:
  shared_addr->b_quit = 1;
  sf_post(&shared_addr->sf_ns_ready);
  return 0;
}
