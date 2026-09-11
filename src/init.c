/* Native routine registration.
 *
 * Two interfaces leave this package, and they are deliberately different
 * kinds of thing:
 *
 *   - .Call entry points, registered below and reached from R.
 *   - A small C API for the zufuzz.libfuzzer companion, registered with
 *     R_RegisterCCallable() and reached with R_GetCCallable().  That is R's
 *     documented mechanism for C between packages; it needs neither
 *     RTLD_GLOBAL nor dynamic symbol lookup, which is why this package does
 *     not load its DLL with library.dynam(local = FALSE).
 */

#include "zufuzz.h"

#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

static const R_CallMethodDef call_methods[] = {
    {"zufuzz_probe", (DL_FUNC) &zufuzz_probe, 1},
    {"zufuzz_region_alloc", (DL_FUNC) &zufuzz_region_alloc, 1},
    {"zufuzz_region_size", (DL_FUNC) &zufuzz_region_size, 0},
    {"zufuzz_region_read", (DL_FUNC) &zufuzz_region_read, 0},
    {"zufuzz_region_reset", (DL_FUNC) &zufuzz_region_reset, 0},
    {"zufuzz_attach_sink", (DL_FUNC) &zufuzz_attach_sink, 3},
    {"zufuzz_sink_mode", (DL_FUNC) &zufuzz_sink_mode, 0},
    {"zufuzz_is_frozen", (DL_FUNC) &zufuzz_is_frozen, 0},
    {"zufuzz_thaw", (DL_FUNC) &zufuzz_thaw, 0},
    {"zufuzz_region_via_ccallable", (DL_FUNC) &zufuzz_region_via_ccallable, 0},
    {"zufuzz_afl_supported", (DL_FUNC) &zufuzz_afl_supported, 0},
    {"zufuzz_afl_attach", (DL_FUNC) &zufuzz_afl_attach, 2},
    {"zufuzz_afl_map_ptr", (DL_FUNC) &zufuzz_afl_map_ptr, 0},
    {"zufuzz_afl_map_size", (DL_FUNC) &zufuzz_afl_map_size, 0},
    {"zufuzz_afl_forkserver", (DL_FUNC) &zufuzz_afl_forkserver, 0},
    {NULL, NULL, 0}
};

attribute_visible void R_init_zufuzz(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    /* Registered symbols only: .Call() by character name is refused, so a
     * probe planted in instrumented code cannot be redirected by anything
     * a user can shadow. */
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);

    /* The companion's half of the seam. It reads the region and registers it
     * with libFuzzer on its own side; it installs the comparison hook that
     * Stage 9's wrappers forward through. Neither symbol is a sanitizer
     * symbol, which is the point. */
    R_RegisterCCallable("zufuzz", "zufuzz_counter_region",
                        (DL_FUNC) &zufuzz_counter_region);
    R_RegisterCCallable("zufuzz", "zufuzz_set_cmp_hook",
                        (DL_FUNC) &zufuzz_set_cmp_hook);
}
