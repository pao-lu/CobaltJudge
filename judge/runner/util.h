#ifndef _UTIL_H_INCLUDED
#define _UTIL_H_INCLUDED

#include <stdint.h>

int try_makedir(const char *dir);
int try_makedir_f(const char *dir, ...);
int rmdir_f(const char *dir, ...);
int write_number(uintmax_t num, const char *dir, ...);
int write_string(const char *str, int len, const char *dir, ...);
intmax_t read_int(const char *dir, ...);

#endif
