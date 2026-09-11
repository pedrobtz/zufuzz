/* Coverage counter region and probe routine.
 *
 * Stage 1 implements this: one uint8_t region sized from the frozen
 * instrumentation plan, a probe routine with the three sink modes from
 * design section 6 (none / afl / libfuzzer), and an accessor registered with
 * R_RegisterCCallable() for the companion package.
 *
 * The rule that outlives every engine decision: this file references no
 * __sanitizer_* symbol in any sink mode.  Registering the region with
 * libFuzzer is the companion's job.  That is what keeps zufuzz on CRAN, and
 * what lets a sanitized R build act as an AFL worker with nothing preloaded.
 */

#include "zufuzz.h"
