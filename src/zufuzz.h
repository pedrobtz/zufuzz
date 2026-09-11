/* Internal declarations shared by zufuzz's C sources.
 *
 * Layering rule (design section 15).  Nothing under src/ may reference a
 * fuzzing engine, and nothing here may terminate the process, write to the
 * standard streams, or send a signal.  A fatal condition is reported with
 * Rf_error(); a crash is signalled from R with tools::pskill().  Code that
 * genuinely needs exit(), abort() or libFuzzer belongs in the
 * zufuzz.libfuzzer companion package, which is distributed outside CRAN.
 *
 * tests/testthat/test-symbols.R enforces this against the built shared
 * object, so it holds for anything a header drags in as well.
 */

#ifndef ZUFUZZ_H
#define ZUFUZZ_H

#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

/* AFL's worker protocol (Stage 6) needs System V shared memory to map the
 * supervisor's coverage bitmap.  Where that is absent -- notably Windows
 * under Rtools -- protocol_afl.c compiles to no-ops and the package loses
 * only the ability to attach to a supervisor.  Everything else, including
 * instrumentation, the data provider, replay, minimization and coverage
 * reporting, is unaffected.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#define ZUFUZZ_HAVE_SHM 0
#else
#define ZUFUZZ_HAVE_SHM 1
#endif

/* protocol_afl.c */
SEXP zufuzz_afl_supported(void);

#endif /* ZUFUZZ_H */
