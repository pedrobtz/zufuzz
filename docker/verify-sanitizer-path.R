#!/usr/bin/env Rscript
#
# End-to-end proof of the sanitized worker path (design section 10).
#
# The unit tests in tests/testthat/test-sanitizer.R parse captured logs. They
# prove the parser reads what a sanitizer writes. They cannot prove the other
# half: that a real sanitized R process, run under zufuzz's documented
# options, produces a log in the shape the parser expects. This script closes
# that gap by building a package with a deliberate heap overflow, provoking
# it, and feeding the result through zufuzz.
#
# Run it on Linux. On macOS the equivalent needs DYLD_INSERT_LIBRARIES, which
# System Integrity Protection strips before it reaches the R that R CMD
# INSTALL spawns -- so Configuration B cannot be exercised there at all, which
# is why design section 10 names Linux as the supported platform for it.
#
#   Rscript docker/verify-sanitizer-path.R
#
# Exits non-zero on the first failed assertion. Skips, with a reason and exit
# status 0, when no sanitizer runtime can be found.

pkgload::load_all(quiet = TRUE)

say <- function(...) cat(..., "\n", sep = "")
fail <- function(...) {
  cat("FAIL: ", ..., "\n", sep = "")
  quit(status = 1L)
}
# A skip exits 0, which is the right answer on a laptop with no sanitizer and
# the wrong one in CI: a job that silently skipped would be a green tick
# proving nothing, which is the exact failure this script exists to catch.
# ZUFUZZ_REQUIRE_SANITIZER=1 turns every skip into a failure.
skip <- function(...) {
  if (nzchar(Sys.getenv("ZUFUZZ_REQUIRE_SANITIZER"))) {
    cat("FAIL: ", ..., "\n", sep = "")
    cat("  (ZUFUZZ_REQUIRE_SANITIZER is set, so a skip is a failure here)\n")
    quit(status = 1L)
  }
  cat("SKIP: ", ..., "\n", sep = "")
  quit(status = 0L)
}

# ---------------------------------------------------------------------------
# Find a runtime to preload.
#
# A package built with -fsanitize=address and loaded into a stock R arrives by
# dlopen, which is too late: ASan must be in the process before the
# interceptors it needs are resolved. It says so itself, in as many words, and
# refuses to run. Preloading is the whole of Configuration B.

asan_runtime <- function() {
  for (cc in c(Sys.getenv("CC", "gcc"), "gcc", "clang")) {
    if (!nzchar(Sys.which(cc))) next
    out <- suppressWarnings(tryCatch(
      system2(cc, c("-print-file-name=libasan.so"), stdout = TRUE, stderr = FALSE),
      error = function(e) character(0)
    ))
    if (length(out) && file.exists(out[[1]]) && basename(out[[1]]) != "libasan.so") {
      return(out[[1]])
    }
    # clang names it differently and does not answer -print-file-name for it.
    out <- suppressWarnings(tryCatch(
      system2(cc, c("-print-resource-dir"), stdout = TRUE, stderr = FALSE),
      error = function(e) character(0)
    ))
    if (length(out)) {
      hits <- Sys.glob(file.path(out[[1]], "lib", "*", "libclang_rt.asan*.so"))
      if (length(hits)) return(hits[[1]])
    }
  }
  NA_character_
}

runtime <- asan_runtime()
if (is.na(runtime)) {
  skip("no ASan runtime found; install libasan or clang's compiler-rt")
}
say("ASan runtime: ", runtime)

# ---------------------------------------------------------------------------
# Build the fixture with sanitizers, into a library of its own.

root <- dirname(sub("^--file=", "", grep("^--file=", commandArgs(), value = TRUE)[1]))
if (!length(root) || is.na(root) || !nzchar(root)) root <- "docker"
src <- file.path(root, "fixture", "zufuzzasan")
if (!dir.exists(src)) fail("fixture package not found at ", src)

lib <- tempfile("zufuzz-asan-lib-")
dir.create(lib, recursive = TRUE)
makevars <- tempfile("zufuzz-makevars-")
writeLines(c(
  "CFLAGS = -g -O1 -fno-omit-frame-pointer -fsanitize=address",
  "LDFLAGS = -fsanitize=address"
), makevars)

# detect_leaks=0 during the install too: R leaves allocations for the OS at
# exit, and without it every step ends in a leak report.
install_env <- c(
  "LD_PRELOAD" = runtime,
  "ASAN_OPTIONS" = unname(sanitizer_options()[["ASAN_OPTIONS"]]),
  "R_MAKEVARS_USER" = makevars
)

say("building the fixture with -fsanitize=address ...")
install <- processx::run(
  file.path(R.home("bin"), "R"),
  c("CMD", "INSTALL", paste0("--library=", lib), src),
  env = c(Sys.getenv(), install_env),
  error_on_status = FALSE
)
if (install$status != 0L) {
  cat(utils::tail(strsplit(install$stderr, "\n")[[1]], 20), sep = "\n")
  fail("the fixture did not build under ASan")
}
say("built.")

# ---------------------------------------------------------------------------
# Provoke the defect, and capture what the sanitizer says about it.

provoke <- function(bytes) {
  script <- tempfile("zufuzz-provoke-", fileext = ".R")
  input <- tempfile("zufuzz-input-")
  writeBin(bytes, input)
  writeLines(sprintf(
    'library(zufuzzasan, lib.loc = %s)\ninvisible(consume(readBin(%s, "raw", 1024L)))\ncat("survived\\n")',
    deparse(lib), deparse(input)
  ), script)
  processx::run(
    file.path(R.home("bin"), "Rscript"),
    c("--vanilla", script),
    env = c(
      Sys.getenv(),
      "LD_PRELOAD" = runtime,
      "ASAN_OPTIONS" = unname(sanitizer_options()[["ASAN_OPTIONS"]]),
      # R's own SIGSEGV handler would turn a native crash into a tidy message.
      "R_NO_SEGV_HANDLER" = "1"
    ),
    error_on_status = FALSE
  )
}

# Without the magic prefix the code takes its ordinary path and nothing
# happens. This is the control: it proves the crash below is the defect and
# not merely "anything at all kills a sanitized R".
say("control: input without the magic prefix ...")
clean <- provoke(charToRaw("harmless input, no prefix here"))
if (!identical(clean$status, 0L)) {
  fail("the control input killed the process (status ", clean$status, ")")
}
if (!is.null(parse_sanitizer_log(clean$stderr))) {
  fail("the control input produced a sanitizer report")
}
say("control survived, as it should.")

say("provoking the overflow ...")
crash <- provoke(charToRaw(paste0("ZUFZ", strrep("A", 64))))

if (identical(crash$status, 0L)) {
  fail("the overflow did not kill the process; the fixture was not sanitized")
}

# ---------------------------------------------------------------------------
# The assertions: what zufuzz makes of a real report.

report <- native_finding(crash$stderr, crash$status)
if (is.null(report)) {
  cat(utils::tail(strsplit(crash$stderr, "\n")[[1]], 25), sep = "\n")
  fail("zufuzz found no finding in a log that killed the process")
}

say("")
say("  kind        : ", report$kind)
say("  category    : ", report$category)
say("  signal      : ", report$signal_name %||% NA)
say("  top frame   : ", if (length(report$top_frames)) report$top_frames[[1]] else "<none>")

if (!identical(report$kind, "asan")) {
  fail("expected an ASan report, got kind '", report$kind, "'")
}
if (!identical(report$category, "heap-buffer-overflow")) {
  fail("expected heap-buffer-overflow, got '", report$category, "'")
}
# abort_on_error=1 is what makes a report end in SIGABRT. Without it ASan
# exits 1 and a supervisor records no crash at all, so this is worth asserting
# rather than assuming.
if (!identical(report$signal, 6L)) {
  fail("expected SIGABRT from abort_on_error=1, got signal ", report$signal)
}
if (!length(report$top_frames) || !any(grepl("C_consume", report$top_frames))) {
  fail("the top frames do not name the function that overflowed: ",
       paste(report$top_frames, collapse = " | "))
}

fp <- fingerprint_sanitizer(report)
if (is.null(fp)) fail("a described defect produced no fingerprint")
say("  fingerprint : ", substr(fp$digest, 1, 16))

# Stability is the property the whole gate rests on. Two runs of the same
# defect differ in pid and in every address; the fingerprint must not.
say("")
say("re-running to check the fingerprint is stable ...")
again <- provoke(charToRaw(paste0("ZUFZ", strrep("A", 64))))
report2 <- native_finding(again$stderr, again$status)
fp2 <- fingerprint_sanitizer(report2)
if (identical(crash$stderr, again$stderr)) {
  fail("the two logs are identical, so this proves nothing about stability")
}
if (!identical(fp$digest, fp2$digest)) {
  fail("the same defect fingerprinted differently: ", fp$digest, " vs ", fp2$digest)
}
say("  stable across runs whose logs differ.")

say("")
say("PASS: a real sanitized process, its report, and zufuzz's reading of it agree.")
