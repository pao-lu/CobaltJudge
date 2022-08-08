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
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>  // for false
#include <stdint.h>   // for intmax_t
#include <stdio.h>    // for printf, puts, NULL
#include <stdlib.h>
#include <string.h>  // for memset, strcpy
#include <sys/mman.h>
#include <unistd.h>  // for getpid
#include <unistd.h>

#include "job_desc.h"           // for job_desc, job_desc::(anonymous), prin...
#include "namespace_process.h"  // for ns_proc_info, main_ns_share
#include "simple_futex.h"       // for sf_wait
#include "worker_thread.h"      // for clone_namespace_process, free_namespa...

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
  for (int i = 0; i < 10; i++) {
    int fd[3];
    if ((fd[0] = open("/dev/shm/in.txt", O_RDONLY | O_CLOEXEC)) == -1) {
      perror("CE infd");
      break;
    }
    if ((fd[1] = open("/dev/shm/out.txt", O_WRONLY | O_CLOEXEC | O_CREAT,
                      0622)) == -1) {
      perror("CE outfd");
      break;
    }
    if ((fd[2] = open("/dev/shm/err.txt", O_WRONLY | O_CLOEXEC | O_CREAT,
                      0622)) == -1) {
      perror("CE errfd");
      break;
    }

    puts("compiling");
    desc.pointer[0] = 0;
    desc.pointer[1] = 0;
    strcpy(desc.home_mount_dir, "/dev/shm/test");
    job_desc_add_argv(&desc, "/usr/bin/gcc");
    job_desc_add_argv(&desc, "/home/main.c");
    job_desc_add_argv(&desc, "-O2");
    job_desc_add_argv(&desc, "-o");
    job_desc_add_argv(&desc, "/home/a.out");
    job_desc_add_envp(&desc, "TMPDIR=/home/tmp");
    desc.fd[0] = fd[0];
    desc.fd[1] = fd[1];
    desc.fd[2] = fd[2];
    desc.disable_execve = false;
    desc.time_limit = 1000;
    desc.memory_limit = 128 << 20;
    desc.output_limit = 0;
    desc.pid_limit = 0;

    send_job(&info, &desc);

    sf_wait(&info.shared_addr->sf_ns_ready);
    print_job_res(&info.shared_addr->j_res);
    close(fd[0]);
    close(fd[1]);
    close(fd[2]);

    if (info.shared_addr->j_res.is_killed == false &&
        info.shared_addr->j_res.return_code == 0 &&
        info.shared_addr->j_res.memory_used > 0) {
      for (int j = 0; j < 100; j++) {
        int fds[2];
        pipe(fds);
        int infd = memfd_create("123", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        int outfd = fds[1];
        int errfd =
            open("/dev/shm/err.txt", O_WRONLY | O_CLOEXEC | O_CREAT, 0622);
        int a = rand() & 0xff, b = rand() & 0xff, s = a + b, n;

        char buf[256];
        n = snprintf(buf, 256, "%d %d\n", a, b);
        printf("writed %d\n", write(infd, buf, n));
        fcntl(infd, F_ADD_SEALS,
              F_SEAL_SEAL | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE);
        fcntl(outfd, F_ADD_SEALS, F_SEAL_SEAL);
        lseek(infd, 0, SEEK_SET);

        desc.pointer[0] = 0;
        desc.pointer[1] = 0;
        strcpy(desc.home_mount_dir, "/dev/shm/test");
        job_desc_add_argv(&desc, "/home/a.out");
        job_desc_add_envp(&desc, "TMPDIR=/home/tmp");
        desc.fd[0] = infd;
        desc.fd[1] = outfd;
        desc.fd[2] = errfd;
        desc.disable_execve = false;
        desc.time_limit = 1000;
        desc.memory_limit = 16 << 20;
        desc.output_limit = 1024 * 1024 * 16;
        desc.pid_limit = 1;

        send_job(&info, &desc);

        sf_wait(&info.shared_addr->sf_ns_ready);

        print_job_res(&info.shared_addr->j_res);

        n = read(fds[0], buf, 256);
        if (n < 0) {
          perror("read");
          goto end;
        }
        n = strtol(buf, NULL, 10);
        if (n != s) {
          printf("%d+%d = %d\n", a, b, n);
          puts("WA");
          goto end;
        }
        puts("-----------------------");
        close(infd);
        close(outfd);
        close(errfd);
        close(fds[0]);
      }
    } else {
      puts("CE");
      break;
    }
  }
end:

  free_namespace_process(&info);
  return 0;
}
