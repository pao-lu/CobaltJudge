/* copied from man 2 futex */
#include <errno.h>        // for EAGAIN, errno
#include <linux/futex.h>  // for FUTEX_WAIT, FUTEX_WAKE
#include <stdatomic.h>    // for atomic_compare_exchange_strong
#include <stddef.h>       // for NULL
#include <stdint.h>       // for uint32_t
#include <syscall.h>      // for SYS_futex
#include <unistd.h>       // for syscall
struct timespec;

static long futex(uint32_t *uaddr, int futex_op, uint32_t val,
                  const struct timespec *timeout, /* or: uint32_t val2 */
                  uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

long sf_wait(uint32_t *val) {
  long s;
  while (1) {
    /* Is the futex available? */
    uint32_t one = 1;
    if (atomic_compare_exchange_strong((_Atomic(uint32_t) *)val, &one, 0))
      break; /* Yes */

    /* Futex is not available; wait */

    s = futex(val, FUTEX_WAIT, 0, NULL, NULL, 0);
    if (s == -1 && errno != EAGAIN) return s;
  }
  return 0;
}

long sf_post(uint32_t *val) {
  long s;

  uint32_t zero = 0;
  if (atomic_compare_exchange_strong((_Atomic(uint32_t) *)val, &zero, 1)) {
    s = futex(val, FUTEX_WAKE, 0x7fffffff, NULL, NULL, 0);
    if (s == -1) return s;
  }
  return 0;
}
