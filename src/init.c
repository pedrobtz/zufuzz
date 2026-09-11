/* Native routine registration.
 *
 * Stage 1 adds the counter region and its probe routine here, and registers
 * the region accessor with R_RegisterCCallable() so the zufuzz.libfuzzer
 * companion can obtain (start, end) through R_GetCCallable() -- the
 * documented cross-package C interface, which needs neither RTLD_GLOBAL nor
 * dynamic symbol lookup.
 */

#include "zufuzz.h"

#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

static const R_CallMethodDef call_methods[] = {
    {"zufuzz_afl_supported", (DL_FUNC) &zufuzz_afl_supported, 0},
    {NULL, NULL, 0}
};

attribute_visible void R_init_zufuzz(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    /* Registered symbols only: .Call() by character name is refused, so a
     * probe planted in instrumented code cannot be redirected by anything
     * a user can shadow. */
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}
