/* AFL worker protocol, child side.
 *
 * Stage 6 implements the rest here, modelled on python-afl: shmat() of the
 * supervisor's 64 KiB coverage bitmap named by __AFL_SHM_ID, the deferred
 * fork server handshake on file descriptors 198/199, and persistent mode.
 * Every routine is a leaf -- none evaluates R code -- so no unwind
 * protection is needed around them.
 *
 * Stage 0 establishes only the platform guard.  The <sys/shm.h> include is
 * deliberately unconditional within the guard so that a platform claiming
 * support but lacking the header fails at build time rather than at the
 * first campaign.
 */

#include "zufuzz.h"

#if ZUFUZZ_HAVE_SHM
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

/* Whether this build can attach to an AFL supervisor.  Consulted by
 * engines() and by engine resolution in fuzz(); reported to the user rather
 * than discovered as a failure mid-campaign. */
SEXP zufuzz_afl_supported(void) {
#if ZUFUZZ_HAVE_SHM
    return Rf_ScalarLogical(TRUE);
#else
    return Rf_ScalarLogical(FALSE);
#endif
}
