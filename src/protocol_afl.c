/* AFL worker protocol, child side.
 *
 * zufuzz speaks AFL's protocol itself rather than vendoring libafl or
 * libhfuzz: the wire format is a 64 KiB byte array plus two file descriptors
 * and has been stable for a decade, which is exactly the property a vendored
 * runtime's internal feedback struct does not have.
 *
 * Two pieces, deliberately independent so each can fail and be diagnosed on
 * its own:
 *
 *   attach       map the supervisor's coverage bitmap named by __AFL_SHM_ID
 *   fork server  the handshake on descriptors 198/199
 *
 * Scope: the *deferred* fork server, without persistent mode. R startup and
 * package loading are paid once, before the handshake; each input then costs
 * one fork. Persistent mode would save that fork, but it doubles the protocol
 * state machine, and for R targets the fork is not the expensive part. Stage
 * 12's benchmarks are what should decide whether to add it.
 *
 * Nothing here evaluates R, so no unwind protection is needed around any of
 * it, and nothing here may end the process: the forked child returns to R and
 * R quits. write(), fork() and waitpid() are permitted by the symbol scan --
 * writing four protocol bytes to descriptor 199 is not a write to R's
 * standard streams, which is what that rule is about.
 */

#include "zufuzz.h"

#if ZUFUZZ_HAVE_SHM
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* AFL's control and status descriptors. Fixed by the protocol. */
#define ZUFUZZ_FORKSRV_FD 198

/* AFL's default bitmap size. AFL_MAP_SIZE can raise it; the supervisor tells
 * us nothing, so a mismatch would silently truncate coverage -- which is why
 * the R side passes the size it expects and this refuses to guess. */
#define ZUFUZZ_DEFAULT_MAP_SIZE 65536

#if ZUFUZZ_HAVE_SHM
static uint8_t *zf_afl_map = NULL;
static size_t zf_afl_map_size = 0;
#endif

/* Whether this build can attach to an AFL supervisor. Consulted by engines()
 * and by engine resolution in fuzz(); reported to the user rather than
 * discovered as a failure mid-campaign. */
SEXP zufuzz_afl_supported(void) {
#if ZUFUZZ_HAVE_SHM
    return Rf_ScalarLogical(TRUE);
#else
    return Rf_ScalarLogical(FALSE);
#endif
}

/* Map the supervisor's bitmap.
 *
 * Two flavours, because AFL++ is built either way and the environment
 * variable carries a different thing in each: a System V segment id on most
 * Linux builds, and a POSIX shared-memory *name* on builds compiled with
 * USEMMAP (the default on macOS). Trying the integer form first and falling
 * back is how a single binary copes with both.
 */
SEXP zufuzz_afl_attach(SEXP id_, SEXP size_) {
#if !ZUFUZZ_HAVE_SHM
    (void) id_;
    (void) size_;
    return Rf_ScalarLogical(FALSE);
#else
    const char *id = CHAR(STRING_ELT(id_, 0));
    double requested = Rf_asReal(size_);
    size_t size = (requested > 0) ? (size_t) requested : ZUFUZZ_DEFAULT_MAP_SIZE;

    if (id == NULL || *id == '\0') {
        return Rf_ScalarLogical(FALSE);
    }

    /* System V: the whole value is a decimal segment id. */
    char *end = NULL;
    long shm_id = strtol(id, &end, 10);
    if (end != NULL && *end == '\0') {
        void *mapped = shmat((int) shm_id, NULL, 0);
        if (mapped != (void *) -1) {
            zf_afl_map = (uint8_t *) mapped;
            zf_afl_map_size = size;
            return Rf_ScalarLogical(TRUE);
        }
    }

    /* POSIX (USEMMAP builds): the value is a shared-memory object name. */
    int fd = shm_open(id, O_RDWR, 0600);
    if (fd < 0) {
        return Rf_ScalarLogical(FALSE);
    }
    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        return Rf_ScalarLogical(FALSE);
    }
    zf_afl_map = (uint8_t *) mapped;
    zf_afl_map_size = size;
    return Rf_ScalarLogical(TRUE);
#endif
}

/* The attached bitmap, as an external pointer, so counters.c can be pointed
 * at it without this file knowing anything about sinks. */
SEXP zufuzz_afl_map_ptr(void) {
#if ZUFUZZ_HAVE_SHM
    if (zf_afl_map == NULL) {
        return R_NilValue;
    }
    return R_MakeExternalPtr(zf_afl_map, R_NilValue, R_NilValue);
#else
    return R_NilValue;
#endif
}

SEXP zufuzz_afl_map_size(void) {
#if ZUFUZZ_HAVE_SHM
    return Rf_ScalarReal((double) zf_afl_map_size);
#else
    return Rf_ScalarReal(0);
#endif
}

/* The deferred fork server handshake.
 *
 * Returns TRUE exactly once per input, in the forked child, which then runs
 * that input and quits. In the parent this never returns: the parent *is* the
 * fork server, and it loops until the supervisor closes the pipe -- at which
 * point it returns FALSE so R can stop cleanly rather than being killed.
 *
 * FALSE on the first write also means "no supervisor is listening", which is
 * how a harness run by hand under `Rscript` falls back to run-once instead of
 * hanging on a descriptor nobody holds.
 */
SEXP zufuzz_afl_forkserver(void) {
#if !ZUFUZZ_HAVE_SHM
    return Rf_ScalarLogical(FALSE);
#else
    uint32_t hello = 0;
    if (write(ZUFUZZ_FORKSRV_FD + 1, &hello, 4) != 4) {
        return Rf_ScalarLogical(FALSE);
    }

    for (;;) {
        uint32_t go = 0;
        ssize_t got = read(ZUFUZZ_FORKSRV_FD, &go, 4);
        if (got != 4) {
            /* The supervisor finished or died. Returning lets R exit through
             * its own path rather than waiting to be killed. */
            return Rf_ScalarLogical(FALSE);
        }

        pid_t child = fork();
        if (child < 0) {
            return Rf_ScalarLogical(FALSE);
        }
        if (child == 0) {
            /* The child must not hold the protocol descriptors: if it did,
             * the supervisor would never see EOF when the server stops. */
            close(ZUFUZZ_FORKSRV_FD);
            close(ZUFUZZ_FORKSRV_FD + 1);
            return Rf_ScalarLogical(TRUE);
        }

        uint32_t pid_word = (uint32_t) child;
        if (write(ZUFUZZ_FORKSRV_FD + 1, &pid_word, 4) != 4) {
            return Rf_ScalarLogical(FALSE);
        }

        int status = 0;
        while (waitpid(child, &status, 0) < 0) {
            if (errno != EINTR) {
                return Rf_ScalarLogical(FALSE);
            }
        }

        uint32_t status_word = (uint32_t) status;
        if (write(ZUFUZZ_FORKSRV_FD + 1, &status_word, 4) != 4) {
            return Rf_ScalarLogical(FALSE);
        }
    }
#endif
}
