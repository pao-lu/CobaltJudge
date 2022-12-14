#include "share_fd.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "job_desc.h"

int worker_send_fd(int fd_socket, int fds[3]) {
  struct msghdr msg;
  char iobuf[1];
  struct iovec iov = {.iov_base = iobuf, .iov_len = 1};

  union {
    char buf[CMSG_SPACE(sizeof(*fds) * 3)];
    struct cmsghdr align;
  } u;

  struct cmsghdr *cmsg;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof(u.buf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(*fds) * 3);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(*fds) * 3);

  if (sendmsg(fd_socket, &msg, MSG_NOSIGNAL) == -1) {
    return -1;
  }

  return 0;
}

int namespace_process_recv_fd(int fd_socket, int fds[3]) {
  ssize_t size;
  struct msghdr msg;
  struct iovec iov;
  union {
    char buf[CMSG_SPACE(sizeof(*fds) * 3)];
    struct cmsghdr align;
  } u;
  struct cmsghdr *cmsg;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof(u.buf);
  size = recvmsg(fd_socket, &msg, MSG_CMSG_CLOEXEC);
  if (size == -1) {
    return -1;
  }
  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg) {
    return -3;
  }
  if (cmsg->cmsg_level != SOL_SOCKET) {
    return -4;
  }
  if (cmsg->cmsg_type != SCM_RIGHTS) {
    return -5;
  }
  if (cmsg->cmsg_len != CMSG_LEN(sizeof(*fds) * 3)) {
    return -6;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(*fds) * 3);
  return 0;
}
