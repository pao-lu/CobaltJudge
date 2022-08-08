#ifndef _SHARE_FD_H_INCLUDED
#define _SHARE_FD_H_INCLUDED

int worker_send_fd(int fd_socket, int fds[3]);
int namespace_process_recv_fd(int fd_socket, int fds[3]);

#endif
