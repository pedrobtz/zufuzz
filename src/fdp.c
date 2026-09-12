/* FuzzedDataProvider: the byte-to-value mapping.
 *
 * Written exactly once, here, because "same bytes, same object" is the
 * invariant the whole structured-input design rests on (design section 11).
 * `fuzzed_data_provider()` and `draw()` are two front doors onto this code; a
 * second implementation in R would drift, and the drift would be silent --
 * corpora would stop meaning what they meant and nobody would notice until a
 * minimized artifact rendered as a different object.
 *
 * Two rules the whole file obeys:
 *
 *   Nothing here can error on any byte sequence. Input is adversarial by
 *   definition; a provider that throws is a defect in the harness reported as
 *   a defect in the target.
 *
 *   Exhaustion is a value, not a failure. Past the end, every method returns
 *   a well-defined zero-ish result and the cursor stops moving.
 *
 * Layout follows LLVM's FuzzedDataProvider: bytes are taken from the front,
 * integers from the back. Corpora and intuitions then carry over from Atheris
 * and from C++ harnesses.
 *
 * This file depends on nothing but R's own API -- no engine, no counters --
 * which is what makes the provider work in a live session, with no engine
 * installed, and on Windows.
 */

#include "zufuzz.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t front; /* next byte to hand out from the front */
    size_t back;  /* one past the last byte available from the back */
} zufuzz_fdp;

static void fdp_finalize(SEXP ptr) {
    zufuzz_fdp *fdp = (zufuzz_fdp *) R_ExternalPtrAddr(ptr);
    if (fdp == NULL) {
        return;
    }
    free(fdp->data);
    free(fdp);
    R_SetExternalPtrAddr(ptr, NULL);
}

static zufuzz_fdp *fdp_from(SEXP ptr) {
    zufuzz_fdp *fdp = (zufuzz_fdp *) R_ExternalPtrAddr(ptr);
    if (fdp == NULL) {
        Rf_error("zufuzz: this data provider is no longer valid");
    }
    return fdp;
}

static size_t fdp_remaining(const zufuzz_fdp *fdp) {
    return (fdp->back > fdp->front) ? (fdp->back - fdp->front) : 0;
}

SEXP zufuzz_fdp_create(SEXP data_) {
    if (TYPEOF(data_) != RAWSXP) {
        Rf_error("zufuzz: a data provider needs a raw vector");
    }
    R_xlen_t n = XLENGTH(data_);

    zufuzz_fdp *fdp = (zufuzz_fdp *) calloc(1, sizeof(zufuzz_fdp));
    if (fdp == NULL) {
        Rf_error("zufuzz: cannot allocate a data provider");
    }
    /* Copied rather than borrowed: the raw vector the caller passed may be
     * garbage collected, reused, or modified, and a provider that silently
     * changed meaning underneath a harness would break reproduction. */
    if (n > 0) {
        fdp->data = (uint8_t *) malloc((size_t) n);
        if (fdp->data == NULL) {
            free(fdp);
            Rf_error("zufuzz: cannot allocate %.0f bytes for a data provider", (double) n);
        }
        memcpy(fdp->data, RAW(data_), (size_t) n);
    }
    fdp->len = (size_t) n;
    fdp->front = 0;
    fdp->back = (size_t) n;

    SEXP ptr = PROTECT(R_MakeExternalPtr(fdp, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, fdp_finalize, TRUE);
    UNPROTECT(1);
    return ptr;
}

SEXP zufuzz_fdp_remaining(SEXP ptr) {
    return Rf_ScalarReal((double) fdp_remaining(fdp_from(ptr)));
}

SEXP zufuzz_fdp_consumed(SEXP ptr) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    return Rf_ScalarReal((double) (fdp->len - fdp_remaining(fdp)));
}

/* -- bytes, from the front ---------------------------------------------- */

SEXP zufuzz_fdp_bytes(SEXP ptr, SEXP n_) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    double requested = Rf_asReal(n_);
    size_t available = fdp_remaining(fdp);

    size_t take;
    if (!R_FINITE(requested) || requested >= (double) available) {
        take = available; /* never more than there is */
    } else if (requested <= 0) {
        take = 0;
    } else {
        take = (size_t) requested;
    }

    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) take));
    if (take > 0) {
        memcpy(RAW(out), fdp->data + fdp->front, take);
        fdp->front += take;
    }
    UNPROTECT(1);
    return out;
}

/* -- integers, from the back -------------------------------------------- */

/* Big-endian from the back, so that consuming an integer and then consuming
 * bytes never overlap. Fewer bytes than asked for is not an error: the value
 * is simply built from what was there. */
static uint64_t fdp_take_back(zufuzz_fdp *fdp, size_t bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; i++) {
        if (fdp_remaining(fdp) == 0) {
            break;
        }
        fdp->back--;
        value = (value << 8) | (uint64_t) fdp->data[fdp->back];
    }
    return value;
}

/* An R integer is 32-bit signed with NA_INTEGER at INT_MIN, so that one value
 * is excluded: a provider that returned NA would make every harness handle a
 * case the fuzzer invented rather than the target's own domain. */
SEXP zufuzz_fdp_int(SEXP ptr, SEXP bits_) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    int bits = Rf_asInteger(bits_);
    if (bits == NA_INTEGER || bits < 1) {
        bits = 32;
    }
    if (bits > 32) {
        bits = 32;
    }
    size_t bytes = (size_t) ((bits + 7) / 8);
    uint64_t raw = fdp_take_back(fdp, bytes);

    if (bits < 32) {
        raw &= (((uint64_t) 1 << bits) - 1);
    }
    int32_t value = (int32_t) (uint32_t) raw;
    if (value == NA_INTEGER) {
        value = INT_MIN + 1;
    }
    return Rf_ScalarInteger(value);
}

/* Inclusive on both ends, uniform over the width, and correct when the width
 * exceeds what a signed 32-bit value can express. */
SEXP zufuzz_fdp_int_in_range(SEXP ptr, SEXP min_, SEXP max_) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    double lo = Rf_asReal(min_);
    double hi = Rf_asReal(max_);
    if (!R_FINITE(lo) || !R_FINITE(hi)) {
        Rf_error("zufuzz: the range must be finite");
    }
    if (lo > hi) {
        double swap = lo;
        lo = hi;
        hi = swap;
    }
    if (lo == hi) {
        return Rf_ScalarInteger((int) lo);
    }

    uint64_t width = (uint64_t) (hi - lo) + 1;
    size_t bytes = 0;
    for (uint64_t w = width - 1; w > 0; w >>= 8) {
        bytes++;
    }
    uint64_t raw = fdp_take_back(fdp, bytes);
    double value = lo + (double) (raw % width);
    return Rf_ScalarInteger((int) value);
}

SEXP zufuzz_fdp_double_in_range(SEXP ptr, SEXP min_, SEXP max_) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    double lo = Rf_asReal(min_);
    double hi = Rf_asReal(max_);
    if (!R_FINITE(lo) || !R_FINITE(hi)) {
        Rf_error("zufuzz: the range must be finite");
    }
    if (lo > hi) {
        double swap = lo;
        lo = hi;
        hi = swap;
    }
    /* 53 bits is what a double can hold exactly, so the fraction is uniform
     * over representable values rather than over a subset of them. */
    uint64_t raw = fdp_take_back(fdp, 8);
    double fraction = (double) (raw >> 11) / (double) ((uint64_t) 1 << 53);
    return Rf_ScalarReal(lo + fraction * (hi - lo));
}

SEXP zufuzz_fdp_probability(SEXP ptr) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    uint64_t raw = fdp_take_back(fdp, 8);
    return Rf_ScalarReal((double) (raw >> 11) / (double) ((uint64_t) 1 << 53));
}

SEXP zufuzz_fdp_bool(SEXP ptr) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    uint64_t raw = fdp_take_back(fdp, 1);
    /* Never NA: a logical that might be NA makes every `if` in a harness a
     * potential error, which is the harness's bug and not the target's. */
    return Rf_ScalarLogical((int) (raw & 1));
}

/* The special values are where real defects live -- NaN and NA_real_ take
 * different paths through most numeric code -- so they are reachable, but
 * only through one byte of the input, which keeps them findable by a mutator
 * rather than constant. */
SEXP zufuzz_fdp_double(SEXP ptr, SEXP allow_special_) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    int allow_special = Rf_asLogical(allow_special_);

    if (allow_special == TRUE) {
        uint64_t selector = fdp_take_back(fdp, 1);
        switch (selector % 16) {
        case 0:
            return Rf_ScalarReal(R_NaN);
        case 1:
            return Rf_ScalarReal(R_PosInf);
        case 2:
            return Rf_ScalarReal(R_NegInf);
        case 3:
            return Rf_ScalarReal(NA_REAL);
        case 4:
            return Rf_ScalarReal(-0.0);
        case 5:
            return Rf_ScalarReal(0.0);
        default:
            break;
        }
    }

    uint64_t raw = fdp_take_back(fdp, 8);
    double value;
    memcpy(&value, &raw, sizeof(value));
    if (!R_FINITE(value)) {
        /* A bit pattern that happens to be NaN or Inf would make
         * allow_special = FALSE a lie, so it is folded back into a finite
         * value rather than passed through. */
        value = (double) (raw >> 11) / (double) ((uint64_t) 1 << 53);
    }
    return Rf_ScalarReal(value);
}

SEXP zufuzz_fdp_reset(SEXP ptr) {
    zufuzz_fdp *fdp = fdp_from(ptr);
    fdp->front = 0;
    fdp->back = fdp->len;
    return R_NilValue;
}

/* -- UTF-8 filtering ----------------------------------------------------- */

/* Keep only well-formed UTF-8 sequences, drop everything else.
 *
 * Done here, in C, rather than with iconv(), because iconv's behaviour on
 * malformed input varies between platforms and even between builds -- and
 * "same bytes, same object" has to hold on Linux, macOS and Windows alike, or
 * a corpus stops meaning the same thing when it moves between machines.
 *
 * Strict RFC 3629: no overlong encodings, no surrogates, nothing above
 * U+10FFFF. A lenient decoder would accept sequences that R itself later
 * rejects, which just moves the problem.
 */
static int zf_continuation(uint8_t b) {
    return (b & 0xC0) == 0x80;
}

SEXP zufuzz_utf8_filter(SEXP bytes_) {
    if (TYPEOF(bytes_) != RAWSXP) {
        Rf_error("zufuzz: expected a raw vector");
    }
    R_xlen_t n = XLENGTH(bytes_);
    const uint8_t *in = (const uint8_t *) RAW(bytes_);

    SEXP out = PROTECT(Rf_allocVector(RAWSXP, n));
    uint8_t *dst = (uint8_t *) RAW(out);
    R_xlen_t kept = 0;
    R_xlen_t i = 0;

    while (i < n) {
        uint8_t b = in[i];
        R_xlen_t len = 0;

        if (b == 0x00) {
            /* R strings cannot hold a NUL at all. */
            i++;
            continue;
        } else if (b < 0x80) {
            len = 1;
        } else if (b >= 0xC2 && b <= 0xDF) {
            if (i + 1 < n && zf_continuation(in[i + 1])) len = 2;
        } else if (b == 0xE0) {
            if (i + 2 < n && in[i + 1] >= 0xA0 && in[i + 1] <= 0xBF &&
                zf_continuation(in[i + 2])) len = 3;
        } else if (b >= 0xE1 && b <= 0xEC) {
            if (i + 2 < n && zf_continuation(in[i + 1]) &&
                zf_continuation(in[i + 2])) len = 3;
        } else if (b == 0xED) {
            /* Surrogates U+D800..U+DFFF are not valid UTF-8. */
            if (i + 2 < n && in[i + 1] >= 0x80 && in[i + 1] <= 0x9F &&
                zf_continuation(in[i + 2])) len = 3;
        } else if (b >= 0xEE && b <= 0xEF) {
            if (i + 2 < n && zf_continuation(in[i + 1]) &&
                zf_continuation(in[i + 2])) len = 3;
        } else if (b == 0xF0) {
            if (i + 3 < n && in[i + 1] >= 0x90 && in[i + 1] <= 0xBF &&
                zf_continuation(in[i + 2]) && zf_continuation(in[i + 3])) len = 4;
        } else if (b >= 0xF1 && b <= 0xF3) {
            if (i + 3 < n && zf_continuation(in[i + 1]) &&
                zf_continuation(in[i + 2]) && zf_continuation(in[i + 3])) len = 4;
        } else if (b == 0xF4) {
            if (i + 3 < n && in[i + 1] >= 0x80 && in[i + 1] <= 0x8F &&
                zf_continuation(in[i + 2]) && zf_continuation(in[i + 3])) len = 4;
        }

        if (len == 0) {
            i++; /* not the start of anything well-formed: drop it */
            continue;
        }
        for (R_xlen_t k = 0; k < len; k++) {
            dst[kept++] = in[i + k];
        }
        i += len;
    }

    SEXP trimmed = PROTECT(Rf_allocVector(RAWSXP, kept));
    if (kept > 0) {
        memcpy(RAW(trimmed), dst, (size_t) kept);
    }
    UNPROTECT(2);
    return trimmed;
}
