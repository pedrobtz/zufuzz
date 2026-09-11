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

#include <stddef.h>
#include <stdint.h>

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

/* Where a probe's increment lands.  Fixed once, when an engine attaches;
 * see counters.c.  Kept in step with sink_mode() in R/counters.R. */
#define ZUFUZZ_SINK_NONE 0
#define ZUFUZZ_SINK_AFL 1
#define ZUFUZZ_SINK_LIBFUZZER 2

/* Installed by the companion package (Stage 9) to forward comparison
 * operands to libFuzzer's __sanitizer_weak_hook_* functions.  Declaring the
 * type here -- rather than the sanitizer functions themselves -- is what
 * keeps the engine's symbols out of this package. */
typedef void (*zufuzz_cmp_hook_fn)(uintptr_t pc, const void *a, const void *b,
                                   size_t n, int result);

/* counters.c */
SEXP zufuzz_probe(SEXP id_);
SEXP zufuzz_region_alloc(SEXP n_);
SEXP zufuzz_region_size(void);
SEXP zufuzz_region_read(void);
SEXP zufuzz_region_reset(void);
SEXP zufuzz_attach_sink(SEXP mode_, SEXP map_);
SEXP zufuzz_sink_mode(void);
SEXP zufuzz_is_frozen(void);
SEXP zufuzz_thaw(void);
SEXP zufuzz_region_via_ccallable(void);

/* counters.c, exported to the companion via R_RegisterCCallable(). */
void zufuzz_counter_region(uint8_t **start, uint8_t **end);
void zufuzz_set_cmp_hook(zufuzz_cmp_hook_fn fn);
void zufuzz_trace_cmp(uintptr_t pc, const void *a, const void *b, size_t n,
                      int result);

/* protocol_afl.c */
SEXP zufuzz_afl_supported(void);

#endif /* ZUFUZZ_H */
