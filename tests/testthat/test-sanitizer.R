# Stage 10: reading a sanitizer report out of a dead process.
#
# Every fixture in tests/testthat/fixtures/sanitizer/ is real output, captured
# from clang 17 by compiling a deliberate defect and running it -- not written
# from memory. That matters more here than usual: the whole file is a parser,
# and a parser tested against invented input only proves it can read what its
# author imagined. Two of the tests below exist because real output disagreed
# with what I had assumed.
#
# None of this needs a sanitizer to run, which is the point: the parser is
# pure, so it is tested identically on a machine that has no ASan at all.

log_fixture <- function(name) {
  readLines(test_path("fixtures", "sanitizer", name), warn = FALSE)
}

test_that("an ASan report yields the fields a sidecar promises", {
  r <- parse_sanitizer_log(log_fixture("asan-linux-over-r.log"))

  expect_identical(r$kind, "asan")
  expect_identical(r$category, "heap-buffer-overflow")
  expect_identical(r$function_name, "zujson_decode_utf8")
  expect_match(r$location, "utf8\\.c:204$")
  expect_match(r$summary, "^SUMMARY: AddressSanitizer")
})

test_that("a UBSan report parses despite having no `in <function>` part", {
  # Real clang output, and the reason this test exists:
  #
  #   SUMMARY: AddressSanitizer: heap-buffer-overflow san.c:10 in main
  #   SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ub.c:2:55<space>
  #
  # Reading the ASan line and requiring " in <function>" -- the obvious
  # reading -- silently drops the location for every UBSan finding.
  r <- parse_sanitizer_log(log_fixture("ubsan-shift.log"))

  expect_identical(r$kind, "ubsan")
  expect_identical(r$category, "undefined-behavior")
  expect_identical(r$location, "ub.c:2:55")
  expect_true(is.na(r$function_name))
  # UBSan describes the defect on its first line, not on an ERROR line.
  expect_match(r$message, "shift exponent 40 is too large")
})

test_that("the frames kept are the ones that name the code under test", {
  r <- parse_sanitizer_log(log_fixture("asan-linux-over-r.log"))

  # Frame #0 of a heap overflow is __asan_memcpy: true, and useless. R's
  # evaluator frames are constant across every finding, so they cannot tell
  # two bugs apart.
  expect_false(any(grepl("__asan_memcpy", r$top_frames)))
  expect_false(any(grepl("bcEval|Rf_eval|R_doDotCall", r$top_frames)))
  expect_match(r$top_frames[[1L]], "zujson_decode_utf8")
})

test_that("only the first stack is kept, not the allocation stack after it", {
  # An ASan report carries several stacks -- where the bad access happened,
  # and separately where the memory was allocated. Concatenating them produces
  # a frame list that reads like one call stack and is not.
  r <- parse_sanitizer_log(log_fixture("asan-heap-overflow.log"))
  expect_length(r$top_frames, 1L)
  expect_false(any(grepl("malloc", r$top_frames)))
})

test_that("the same defect fingerprints the same across runs", {
  # Two real runs of one binary. The logs differ as text -- different pid,
  # different ASLR addresses -- and a fingerprint that followed those would
  # match nothing and gate nothing.
  a <- log_fixture("asan-heap-overflow.log")
  b <- log_fixture("asan-heap-overflow-rerun.log")
  expect_false(identical(a, b))

  fa <- fingerprint_sanitizer(parse_sanitizer_log(a))
  fb <- fingerprint_sanitizer(parse_sanitizer_log(b))
  expect_identical(fa$digest, fb$digest)
})

test_that("the same defect fingerprints the same from a different build tree", {
  # A container, a reviewer's checkout and CI all build in different
  # directories. If the path went into the fingerprint, every confirmed
  # reproduction would be reported as a different bug.
  original <- log_fixture("asan-linux-over-r.log")
  moved <- gsub("/src/zujson/src/", "/home/reviewer/pkg/src/", original, fixed = TRUE)
  expect_false(identical(original, moved))

  expect_identical(
    fingerprint_sanitizer(parse_sanitizer_log(original))$digest,
    fingerprint_sanitizer(parse_sanitizer_log(moved))$digest
  )
})

test_that("different defects fingerprint differently", {
  overflow <- fingerprint_sanitizer(parse_sanitizer_log(log_fixture("asan-linux-over-r.log")))
  shift <- fingerprint_sanitizer(parse_sanitizer_log(log_fixture("ubsan-shift.log")))
  expect_false(identical(overflow$digest, shift$digest))
})

test_that("a bare signal is recorded but never fingerprinted", {
  # Design section 10: a death with no report has nothing stable to hash, so
  # claiming a fingerprint would let minimize() shrink one crash into another
  # and call it the same bug.
  r <- native_finding(log_fixture("no-report.log"), status = 139L)

  expect_identical(r$kind, "signal")
  expect_identical(r$signal, 11L)
  expect_identical(r$signal_name, "SIGSEGV")
  expect_true(is.na(r$category))
  expect_null(fingerprint_sanitizer(r))
  expect_match(r$message, "no sanitizer report")
})

test_that("a report cut off before its SUMMARY is classified but not fingerprinted", {
  # The process was killed mid-write. Recognising the ERROR line keeps the
  # finding filed as ASan rather than as a bare signal, but there is no
  # category to compare, so sameness still cannot be claimed.
  r <- parse_sanitizer_log(log_fixture("asan-truncated.log"))

  expect_identical(r$kind, "asan")
  expect_true(isTRUE(r$truncated))
  expect_true(is.na(r$category))
  expect_null(fingerprint_sanitizer(r))
})

test_that("a leak report is a configuration fault, not a finding", {
  # zufuzz disables LSan on purpose: R leaves allocations for the OS at exit.
  # A leak report therefore means detect_leaks=0 never reached the process.
  # Filing it as a defect would send someone after R's own exit behaviour --
  # and its SUMMARY is a sentence, so the generic parse reads "8" as the
  # category.
  r <- parse_sanitizer_log(log_fixture("lsan-leak.log"))

  expect_identical(r$kind, "lsan")
  expect_true(isTRUE(r$misconfigured))
  expect_true(is.na(r$category))
  expect_null(fingerprint_sanitizer(r))
  expect_match(r$message, "detect_leaks=0 did not")
})

test_that("a clean run is not a finding", {
  expect_null(parse_sanitizer_log("all inputs ran"))
  expect_null(parse_sanitizer_log(character(0)))
  expect_null(parse_sanitizer_log(NULL))
  # Exit status zero and no report: nothing happened.
  expect_null(native_finding("all inputs ran", status = 0L))
})

test_that("signals are read from an exit status the way a shell reports them", {
  expect_identical(death_by_signal(134L), 6L)
  expect_identical(death_by_signal(139L), 11L)
  expect_identical(death_by_signal(-9L), 9L)
  expect_true(is.na(death_by_signal(0L)))
  expect_true(is.na(death_by_signal(1L)))
  expect_true(is.na(death_by_signal(NA_integer_)))
  expect_true(is.na(death_by_signal(NULL)))
})

test_that("the documented options are the ones design section 10 justifies", {
  opts <- sanitizer_options()
  # Each of these earns its place, and abort_on_error is load-bearing: without
  # it ASan exits 1 and a supervisor records no crash at all.
  expect_match(opts[["ASAN_OPTIONS"]], "abort_on_error=1")
  expect_match(opts[["ASAN_OPTIONS"]], "detect_leaks=0")
  expect_match(opts[["ASAN_OPTIONS"]], "allocator_may_return_null=1")
  expect_match(opts[["UBSAN_OPTIONS"]], "halt_on_error=1")
  expect_match(opts[["UBSAN_OPTIONS"]], "print_stacktrace=1")
})

test_that("the runtime is detected from the process map, not from intent", {
  # Fixture maps files, so this runs on every platform rather than only where
  # /proc exists.
  expect_identical(
    maps_evidence(test_path("fixtures", "sanitizer", "maps-sanitized.txt")),
    "asan"
  )
  expect_length(
    maps_evidence(test_path("fixtures", "sanitizer", "maps-plain.txt")), 0L
  )
  expect_null(maps_evidence(tempfile("definitely-not-here-")))
})

test_that("status never claims sanitized without proof, and says so when it cannot tell", {
  st <- sanitizer_status()
  expect_s3_class(st, "zufuzz_sanitizer_status")
  expect_type(st$sanitized, "logical")

  # An env var says what was asked for, never what happened. On a machine with
  # no sanitizer this must still report unsanitized.
  old <- Sys.getenv("LD_PRELOAD", unset = NA)
  Sys.setenv(LD_PRELOAD = "/nowhere/libasan.so.8")
  on.exit(
    if (is.na(old)) Sys.unsetenv("LD_PRELOAD") else Sys.setenv(LD_PRELOAD = old),
    add = TRUE
  )
  faked <- sanitizer_status()
  if (!faked$detectable) {
    expect_false(faked$sanitized)
  }
  # It is still reported as evidence -- the user should see the mismatch.
  expect_true(any(grepl("preloaded", faked$evidence)))
})

test_that("the status prints, and an undetectable platform says so", {
  st <- sanitizer_status()
  out <- capture.output(print(st))
  expect_true(any(grepl("zufuzz sanitizer status", out)))
  if (!st$detectable) {
    # "not sanitized" would be a claim; this platform cannot support one.
    expect_true(any(grepl("unknown", out)))
  }
})

test_that("asking for a sanitizer and not getting one is reported", {
  # The quiet failure this prevents: a campaign that was believed to be
  # sanitized runs, finds less, and exits zero -- indistinguishable from a
  # clean result. The status is injected so this is exercised on every
  # platform, not only where /proc/self/maps exists.
  detectable_plain <- list(detectable = TRUE, sanitized = FALSE)
  expect_warning(
    warn_if_unsanitized(c(ASAN_OPTIONS = "detect_leaks=0"), detectable_plain),
    "will run unsanitized"
  )

  # Actually sanitized: nothing to say.
  expect_silent(
    warn_if_unsanitized(
      c(ASAN_OPTIONS = "detect_leaks=0"),
      list(detectable = TRUE, sanitized = TRUE)
    )
  )
  # No sanitizer asked for: not this function's business.
  expect_silent(warn_if_unsanitized(c(FOO = "bar"), detectable_plain))
  expect_silent(warn_if_unsanitized(character(0), detectable_plain))
  # Cannot tell: staying quiet beats nagging about something unverifiable.
  expect_silent(
    warn_if_unsanitized(
      c(ASAN_OPTIONS = "x"),
      list(detectable = FALSE, sanitized = FALSE)
    )
  )
})

test_that("replay reports a native death without inventing a fingerprint", {
  # classify_replay() is the seam where a log becomes a finding, so it is
  # checked directly rather than by arranging a real segfault in a test.
  segv <- classify_replay(
    list(status = 139L, stderr = "", timeout = FALSE),
    tempfile("no-sidecars-")
  )
  expect_identical(segv$outcome, "signal")
  expect_null(segv$fingerprint)

  report <- paste(readLines(
    test_path("fixtures", "sanitizer", "asan-linux-over-r.log"),
    warn = FALSE
  ), collapse = "\n")
  asan <- classify_replay(
    list(status = 134L, stderr = report, timeout = FALSE),
    tempfile("no-sidecars-")
  )
  expect_identical(asan$outcome, "sanitizer")
  expect_true(nzchar(asan$fingerprint))
  expect_identical(asan$native$category, "heap-buffer-overflow")

  # Exited non-zero with no report and no signal: the harness failed to load.
  # Calling that a crash would invent a finding.
  broken <- classify_replay(
    list(status = 1L, stderr = "there is no package called 'nope'", timeout = FALSE),
    tempfile("no-sidecars-")
  )
  expect_identical(broken$outcome, "infrastructure")
  expect_null(broken$fingerprint)
})

test_that("minimize explains why a native finding cannot be shrunk", {
  signal <- native_finding("nothing to report", status = 139L)
  expect_match(refuse_native_minimize(signal), "bare SIGSEGV")
  expect_match(refuse_native_minimize(signal), "same thing")

  leak <- parse_sanitizer_log(log_fixture("lsan-leak.log"))
  expect_match(refuse_native_minimize(leak), "detect_leaks=0")

  # A described defect can be shrunk, so there is nothing to refuse.
  asan <- parse_sanitizer_log(log_fixture("asan-linux-over-r.log"))
  expect_null(refuse_native_minimize(asan))
  expect_null(refuse_native_minimize(NULL))
})

# The rest of this file works on logs captured from a small C binary. This one
# is the real thing: a heap overflow inside a .Call, in a package built with
# -fsanitize=address, under a stock Linux R, captured by
# docker/verify-sanitizer-path.R in CI. It is the only fixture here with R's
# evaluator in the stack and with glibc's fortified wrappers in it, and it is
# the shape that exposed a bug no hand-written fixture did.

test_that("glibc's fortified wrapper does not become the defect", {
  r <- parse_sanitizer_log(log_fixture("asan-glibc-fortified.log"))

  # An overflow through memcpy reports the inline wrapper from
  # /usr/include/.../string_fortified.h *before* the caller that got the
  # length wrong. That frame is byte identical for every memcpy overflow in
  # every package, so building the fingerprint on it merged unrelated bugs.
  expect_match(r$top_frames[[1L]], "C_consume")
  expect_false(any(grepl("string_fortified|/usr/include/", r$top_frames)))
})

test_that("R's evaluator is filtered out of a real in-process crash", {
  r <- parse_sanitizer_log(log_fixture("asan-glibc-fortified.log"))
  # This stack has seventeen frames of R below the defect. They are identical
  # for every finding reached through .Call, so they cannot tell two bugs
  # apart, and they would bury the one frame anybody wants to see.
  expect_false(any(grepl(
    "bcEval|Rf_eval|R_doDotCall|R_execClosure|run_Rmainloop|_start|__libc_start_main",
    r$top_frames
  )))
  expect_true(length(r$top_frames) >= 1L)
})

test_that("the SUMMARY is kept verbatim even when it names a libc wrapper", {
  r <- parse_sanitizer_log(log_fixture("asan-glibc-fortified.log"))

  # The sanitizer's own words are recorded unedited -- rewriting them would
  # make the sidecar disagree with the log a reader is holding. So
  # `function_name` here really is "memcpy", straight out of the SUMMARY
  # line, and `top_frames[[1]]` is the answer worth acting on. The two fields
  # mean different things and this is the case that shows it.
  expect_match(r$summary, "^SUMMARY: AddressSanitizer: heap-buffer-overflow")
  expect_identical(r$function_name, "memcpy")
  expect_match(r$location, "string_fortified\\.h:29$")
  expect_match(r$top_frames[[1L]], "C_consume")
})

test_that("a real in-process overflow fingerprints on the package's own frame", {
  original <- log_fixture("asan-glibc-fortified.log")
  fp <- fingerprint_sanitizer(parse_sanitizer_log(original))

  expect_false(is.null(fp))
  expect_match(fp$call, "C_consume")
  expect_false(grepl("/home/runner", fp$call))

  # CI, a container and a reviewer's checkout build in different directories.
  moved <- gsub(
    "/home/runner/work/zufuzz/zufuzz/", "/build/pkg/", original,
    fixed = TRUE
  )
  expect_false(identical(original, moved))
  expect_identical(
    fp$digest,
    fingerprint_sanitizer(parse_sanitizer_log(moved))$digest
  )
})
