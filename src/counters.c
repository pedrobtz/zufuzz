/* Coverage counter region and probe routine.
 *
 * One uint8_t region per process, sized from the instrumentation plan and
 * frozen when an engine attaches.  Probes planted by R/instrument.R (Stage 3)
 * call zufuzz_probe() with a dense site id; where that increment lands is the
 * sink mode, chosen once at attach time:
 *
 *   none       region[id]++            read back by coverage_out
 *   libfuzzer  region[id]++            the companion registers the region
 *   afl        map[id ^ prev]++        into the supervisor's shared bitmap
 *              prev = id >> 1
 *
 * The rule that outlives every engine decision: this file references no
 * __sanitizer_* symbol in any mode.  Registering the region with libFuzzer is
 * the companion's job, done through R_GetCCallable("zufuzz",
 * "zufuzz_counter_region").  That is what keeps zufuzz on CRAN, and what lets
 * a sanitized R build act as an AFL worker with nothing preloaded.
 *
 * Nothing here may end the process, signal it, or write to the standard
 * streams; a fatal condition is Rf_error().  tests/testthat/test-symbols.R
 * enforces that against the built object.
 */

#include "zufuzz.h"

#include <R_ext/Rdynload.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The region, and whether it may still be resized. */
static uint8_t *zf_region = NULL;
static size_t zf_region_n = 0;
static int zf_frozen = 0;

/* The sink. zf_afl_map is borrowed, never owned: in tests it is a raw vector
 * preserved on the R side, and from Stage 6 it is the supervisor's shared
 * memory. zf_afl_mask makes the wrap a mask rather than a division, which is
 * why the map size must be a power of two. */
static int zf_sink = ZUFUZZ_SINK_NONE;
static uint8_t *zf_afl_map = NULL;
static size_t zf_afl_mask = 0;
static uint32_t zf_afl_prev = 0;
static SEXP zf_afl_holder = NULL;

/* Comparison forwarding (design section 5).  Stage 9 has the companion
 * install a hook here that forwards operand bytes to libFuzzer's
 * __sanitizer_weak_hook_* functions.  Until then, and under every other
 * sink, the call is a no-op -- but the call site exists from now on, so the
 * rewrite in Stage 9 changes only what the hook does, never where it is. */
static zufuzz_cmp_hook_fn zf_cmp_hook = NULL;

/* -- the probe ---------------------------------------------------------- */

/* Hot path: one call per instrumented branch, so it stays branch-predictable
 * and allocates nothing. A site id out of range is a zufuzz bug, not user
 * error, so it is checked only in debug builds; in a release build the
 * region bound is still honoured so a stale id cannot corrupt memory. */
static void zf_probe_hit(uint32_t id) {
    if (zf_sink == ZUFUZZ_SINK_AFL) {
        if (zf_afl_map != NULL) {
            zf_afl_map[(id ^ zf_afl_prev) & zf_afl_mask]++;
            zf_afl_prev = id >> 1;
        }
        return;
    }
    if (zf_region != NULL && (size_t) id < zf_region_n) {
        zf_region[id]++;
    }
}

SEXP zufuzz_probe(SEXP id_) {
    int id = Rf_asInteger(id_);
#ifndef NDEBUG
    if (id == NA_INTEGER || id < 0) {
        Rf_error("zufuzz: probe called with an invalid site id");
    }
    if (zf_region != NULL && (size_t) id >= zf_region_n) {
        Rf_error(
            "zufuzz: probe site id %d is outside the counter region (%d sites)",
            id, (int) zf_region_n
        );
    }
#endif
    if (id != NA_INTEGER && id >= 0) {
        zf_probe_hit((uint32_t) id);
    }
    return R_NilValue;
}

/* -- the region --------------------------------------------------------- */

SEXP zufuzz_region_alloc(SEXP n_) {
    double n = Rf_asReal(n_);

    if (!R_FINITE(n) || n < 0) {
        Rf_error("zufuzz: counter region size must be a non-negative number");
    }
    if (zf_frozen) {
        Rf_error(
            "zufuzz: the counter region is frozen; instrumentation must be "
            "complete before an engine attaches"
        );
    }

    uint8_t *fresh = NULL;
    if (n > 0) {
        fresh = (uint8_t *) calloc((size_t) n, sizeof(uint8_t));
        if (fresh == NULL) {
            Rf_error("zufuzz: cannot allocate a counter region of %.0f sites", n);
        }
    }

    free(zf_region);
    zf_region = fresh;
    zf_region_n = (size_t) n;
    return Rf_ScalarReal((double) zf_region_n);
}

SEXP zufuzz_region_size(void) {
    return Rf_ScalarReal((double) zf_region_n);
}

/* A copy, so R can never hold a pointer into the live region. */
SEXP zufuzz_region_read(void) {
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) zf_region_n));
    if (zf_region_n > 0) {
        memcpy(RAW(out), zf_region, zf_region_n);
    }
    UNPROTECT(1);
    return out;
}

SEXP zufuzz_region_reset(void) {
    if (zf_region != NULL) {
        memset(zf_region, 0, zf_region_n);
    }
    zf_afl_prev = 0;
    return R_NilValue;
}

/* -- the sink ----------------------------------------------------------- */

SEXP zufuzz_attach_sink(SEXP mode_, SEXP map_, SEXP size_) {
    int mode = Rf_asInteger(mode_);

    if (mode != ZUFUZZ_SINK_NONE && mode != ZUFUZZ_SINK_AFL &&
        mode != ZUFUZZ_SINK_LIBFUZZER) {
        Rf_error("zufuzz: unknown sink mode");
    }

    if (mode == ZUFUZZ_SINK_AFL) {
        /* Two shapes, because the map has two sources: a raw vector, which is
         * how a test supplies one, and an external pointer into shared
         * memory, which is what an attached supervisor gives us. Only the raw
         * vector can be preserved -- shm is owned by the supervisor and
         * outlives this process. */
        uint8_t *map = NULL;
        R_xlen_t n = 0;

        if (TYPEOF(map_) == RAWSXP) {
            map = RAW(map_);
            n = XLENGTH(map_);
        } else if (TYPEOF(map_) == EXTPTRSXP) {
            map = (uint8_t *) R_ExternalPtrAddr(map_);
            n = (R_xlen_t) Rf_asReal(size_);
            if (map == NULL) {
                Rf_error("zufuzz: the AFL coverage map pointer is NULL");
            }
        } else {
            Rf_error("zufuzz: the AFL sink needs a raw vector or a map pointer");
        }

        if (n < 2 || (n & (n - 1)) != 0) {
            Rf_error(
                "zufuzz: the AFL coverage map must be a power of two in size, "
                "not %.0f bytes", (double) n
            );
        }
        if (zf_afl_holder != NULL) {
            R_ReleaseObject(zf_afl_holder);
            zf_afl_holder = NULL;
        }
        if (TYPEOF(map_) == RAWSXP) {
            R_PreserveObject(map_);
            zf_afl_holder = map_;
        }
        zf_afl_map = map;
        zf_afl_mask = (size_t) n - 1;
    } else {
        if (zf_afl_holder != NULL) {
            R_ReleaseObject(zf_afl_holder);
            zf_afl_holder = NULL;
        }
        zf_afl_map = NULL;
        zf_afl_mask = 0;
    }

    zf_sink = mode;
    zf_afl_prev = 0;
    /* Attaching freezes the plan: a site id handed out before the engine
     * started must still mean the same counter afterwards. */
    zf_frozen = 1;
    return Rf_ScalarInteger(zf_sink);
}

SEXP zufuzz_sink_mode(void) {
    return Rf_ScalarInteger(zf_sink);
}

SEXP zufuzz_is_frozen(void) {
    return Rf_ScalarLogical(zf_frozen);
}

/* Test and development only: lets the suite exercise the freeze rule more
 * than once in a session. An engine never thaws a region. */
SEXP zufuzz_thaw(void) {
    zf_frozen = 0;
    zf_sink = ZUFUZZ_SINK_NONE;
    if (zf_afl_holder != NULL) {
        R_ReleaseObject(zf_afl_holder);
        zf_afl_holder = NULL;
    }
    zf_afl_map = NULL;
    zf_afl_mask = 0;
    zf_afl_prev = 0;
    return R_NilValue;
}

/* -- the cross-package C interface -------------------------------------- */

/* Registered with R_RegisterCCallable() in init.c.  The companion calls this
 * to learn where the region is, then hands (start, end) to
 * __sanitizer_cov_8bit_counters_init() on its own side of the boundary.
 * This is R's documented mechanism for C between packages, and it needs
 * neither RTLD_GLOBAL nor dynamic symbol lookup. */
void zufuzz_counter_region(uint8_t **start, uint8_t **end) {
    if (start != NULL) {
        *start = zf_region;
    }
    if (end != NULL) {
        *end = (zf_region == NULL) ? NULL : zf_region + zf_region_n;
    }
}

void zufuzz_set_cmp_hook(zufuzz_cmp_hook_fn fn) {
    zf_cmp_hook = fn;
}

/* Called by the comparison wrappers planted in Stage 9. Forwards only when a
 * companion is attached; otherwise the comparison is simply not traced. */
void zufuzz_trace_cmp(uintptr_t pc, const void *a, const void *b, size_t n,
                      int result) {
    if (zf_cmp_hook != NULL) {
        zf_cmp_hook(pc, a, b, n, result);
    }
}

/* Proves the registration path the companion will use, without building a
 * second package inside R CMD check: resolve the accessor through
 * R_GetCCallable exactly as the companion does, and report the region it
 * reports. Returns the number of counters it can see. */
SEXP zufuzz_region_via_ccallable(void) {
    void (*accessor)(uint8_t **, uint8_t **) =
        (void (*)(uint8_t **, uint8_t **))
        R_GetCCallable("zufuzz", "zufuzz_counter_region");

    uint8_t *start = NULL;
    uint8_t *end = NULL;
    accessor(&start, &end);

    if (start == NULL || end == NULL) {
        return Rf_ScalarReal(0);
    }
    return Rf_ScalarReal((double) (end - start));
}
