#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP C_consume(SEXP);

static const R_CallMethodDef CallEntries[] = {
    {"C_consume", (DL_FUNC) &C_consume, 1},
    {NULL, NULL, 0}
};

void R_init_zufuzzasan(DllInfo *dll) {
    R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
