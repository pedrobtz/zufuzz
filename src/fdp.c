/* FuzzedDataProvider cursor and the byte-to-value mapping.
 *
 * Stage 8 implements this: the consumption algorithm from design section 11,
 * shared by fuzzed_data_provider() and by draw().  The mapping is written
 * exactly once, here, because "same bytes, same object" is the invariant the
 * whole structured-input design rests on and two implementations would
 * drift.
 *
 * This file depends on nothing but R's own API -- no engine, no counters --
 * which is what makes the provider and generator work in a live session,
 * with no engine installed, and on Windows.
 */

#include "zufuzz.h"
