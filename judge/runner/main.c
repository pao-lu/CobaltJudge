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

#include "namespace_process.h"
#include "simple_futex.h"

int main() {
  struct ns_proc_info info;
  if (clone_namespace_process(&info) == 0) {
    sf_wait(&info.shared_addr->sf_ns_ready);
    free_namespace_process(&info);
  }
  return 0;
}
