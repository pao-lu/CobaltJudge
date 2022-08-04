#include <stdint.h>

/* atomically wait until *val == 1 and change to 0 */
long sf_wait(uint32_t *val);

/* change val to 1 */
long sf_post(uint32_t *val);
