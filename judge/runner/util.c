#include "util.h"

#include <errno.h>     // for ENOENT, errno
#include <fcntl.h>     // for open, O_CLOEXEC, O_SYNC, O_WRONLY
#include <stdarg.h>    // for va_end, va_list, va_start
#include <stdint.h>    // for intmax_t, uintmax_t
#include <stdio.h>     // for vsnprintf, fclose, fopen, fscanf, snprintf, FILE
#include <sys/stat.h>  // for stat, mkdir
#include <unistd.h>    // for close, write, rmdir

int try_makedir(const char *dir) {
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

int try_makedir_f(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  return try_makedir(tmp);
}

int rmdir_f(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  return rmdir(tmp);
}

int write_number(uintmax_t num, const char *dir, ...) {
  va_list ap;
  char tmp[256];
  int len, fd, res = 0;
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  fd = open(tmp, O_WRONLY | O_CLOEXEC | O_SYNC);
  if (fd == -1) {
    return -1;
  }
  len = snprintf(tmp, 256, "%ju\n", num);
  if (write(fd, tmp, len) == -1) {
    res = -1;
  }
  if (close(fd) == -1) {
    res = -1;
  }

  return res;
}

int write_string(const char *str, int len, const char *dir, ...) {
  va_list ap;
  char tmp[256];
  int fd, res = 0;
  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  fd = open(tmp, O_WRONLY | O_CLOEXEC | O_SYNC);
  if (fd == -1) {
    return -1;
  }
  if (write(fd, str, len) == -1) {
    res = -1;
  }
  if (close(fd) == -1) {
    res = -1;
  }

  return res;
}

intmax_t read_int(const char *dir, ...) {
  va_list ap;
  char tmp[256];
  intmax_t res;

  va_start(ap, dir);
  vsnprintf(tmp, 256, dir, ap);
  va_end(ap);
  FILE *file = fopen(tmp, "r");
  if (file == NULL) {
    return -1;
  }
  if (fscanf(file, "%jd", &res) != 1) {
    res = -1;
  }
  fclose(file);

  return res;
}
