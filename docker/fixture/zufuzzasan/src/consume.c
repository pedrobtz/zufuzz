#include <R.h>
#include <Rinternals.h>
#include <string.h>
#include <stdlib.h>

/* One defect, behind a four-byte magic prefix, so that reaching it is a
   coverage problem rather than a lottery. Everything else is a normal,
   correct path. */
SEXP C_consume(SEXP data) {
    R_xlen_t n = XLENGTH(data);
    const unsigned char *p = (const unsigned char *) RAW(data);

    if (n < 4) return ScalarInteger(0);
    if (!(p[0] == 'Z' && p[1] == 'U' && p[2] == 'F' && p[3] == 'Z'))
        return ScalarInteger(1);

    /* Reached only with the prefix: copy the remainder into a fixed 8-byte
       buffer without checking that it fits. */
    char *buf = (char *) malloc(8);
    if (buf == NULL) return ScalarInteger(-1);
    memcpy(buf, p + 4, (size_t)(n - 4));
    int out = (int) buf[0];
    free(buf);
    return ScalarInteger(out);
}
