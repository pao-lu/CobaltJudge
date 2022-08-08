#include "job_desc.h"

#include <malloc.h>
#include <stdio.h>
#include <string.h>

void print_job_res(const struct job_result *res) {
  printf("init_result:\t%d\n", res->init_result);
  printf("time_used:\t%ju\n", (uintmax_t)res->time_used);
  printf("memory_used:\t%ju\n", (uintmax_t)res->memory_used);
  printf("is_ole:\t%d\n", res->is_ole);
  printf("is_mle:\t%d\n", res->is_mle);
  printf("is_tle:\t%d\n", res->is_tle);
  printf("is_illegal:\t%d\n", res->is_illegal);
  printf("is_killed:\t%d\n", res->is_killed);
  if (res->is_killed) {
    printf("kill_signal:\t%s\n", strsignal(res->kill_signal));
  } else {
    printf("return_code:\t%d\n", res->return_code);
  }
  printf("errsv:\t%s\n", strerror(res->errsv));
}

int job_desc_add(char *buf, int *pointer, const char *str) {
  int len = strnlen(str, 1024);
  int p = *pointer;
  if (p >= 1024 - 2 - len) {
    return -1;
  }
  memcpy(buf + p, str, len);
  p += len;
  buf[p++] = 0;
  buf[p] = 0;
  *pointer = p;
  return 0;
}

const char **get_packed_args(const char *buf) {
  int p = 0, i, n = 0;
  size_t size_res;
  const char **addr;
  while (p < 1024 && buf[p] != '\0') {
    for (i = p; i < 1024 && buf[i] != '\0'; i++)
      ;
    if (i < 1024) n++;
    p = i + 1;
  }
  size_res = (n + 1) * sizeof(char *);
  addr = (const char **)malloc(size_res);
  p = 0, n = 0;
  while (p < 1024) {
    addr[n] = buf + p;
    if (buf[p] != '\0') {
      for (i = p; i < 1024 && buf[i] != '\0'; i++)
        ;
      if (i < 1024) n++;
      p = i + 1;
    } else
      break;
  }
  addr[n] = 0;
  return addr;
}
