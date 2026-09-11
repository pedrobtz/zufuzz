# Stage 4: what makes two findings the same finding.
#
# The property that matters most is negative: a fingerprint must NOT depend on
# the input. Get that wrong and every input produces a new fingerprint, so
# nothing ever matches anything, minimization can never confirm progress, and
# replay can never say "confirmed".

condition_from <- function(expr) {
  tryCatch(expr, error = function(e) e)
}

test_that("a call is normalised to its function and arity", {
  expect_identical(normalize_call(quote(parse(text = x))), "parse/1")
  expect_identical(normalize_call(quote(f(a, b, c))), "f/3")
  expect_identical(normalize_call(quote(pkg::fn(a))), "pkg::fn/1")
  expect_identical(normalize_call(NULL), "")
})

test_that("the fingerprint does not depend on the input", {
  # The whole point. A call usually carries the offending value, so keeping it
  # verbatim would make every input its own finding.
  fail_on <- function(value) {
    tryCatch(stop("bad value: fixed message"), error = function(e) e)
  }
  a <- fingerprint_condition(fail_on("aaaa"))
  b <- fingerprint_condition(fail_on("bbbbbbbb"))
  expect_identical(a$digest, b$digest)
})

test_that("different defects fingerprint differently", {
  a <- fingerprint_condition(condition_from(stop("first")))
  b <- fingerprint_condition(condition_from(stop("second")))
  expect_false(identical(a$digest, b$digest))

  typed <- condition_from(stop(structure(
    class = c("custom_error", "error", "condition"),
    list(message = "first", call = NULL)
  )))
  plain <- condition_from(stop("first"))
  # Same message, different class: a different defect.
  expect_false(identical(
    fingerprint_condition(typed)$digest,
    fingerprint_condition(plain)$digest
  ))
})

test_that("the fingerprint is stable across processes", {
  skip_if(is.na(installed_zufuzz_lib()), "zufuzz is not installed")

  script <- "
    lib <- Sys.getenv('ZUFUZZ_TEST_LIB'); if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
    library(zufuzz)
    e <- tryCatch(stop('a stable message'), error = function(e) e)
    cat(zufuzz:::fingerprint_condition(e)$digest)
  "
  one <- run_rscript_expr(script)
  two <- run_rscript_expr(script)
  expect_true(nzchar(one))
  expect_identical(one, two)

  local <- fingerprint_condition(condition_from(stop("a stable message")))$digest
  expect_identical(one, local)
})

test_that("the traceback is bounded and marks its truncation", {
  calls <- lapply(seq_len(50), function(i) bquote(frame_.(i)()))
  tb <- bounded_traceback(calls, limit = 5L)
  expect_length(tb, 6L)
  expect_match(tb[[6L]], "45 more frame\\(s\\) not recorded")
})

test_that("zufuzz's own frames are stripped", {
  calls <- list(quote(run_one_input(x)), quote(user_function(y)), quote(fuzz(z)))
  expect_identical(strip_zufuzz_frames(calls), "user_function(y)")
})

test_that("the expected-fingerprint gate reads the environment", {
  old <- Sys.getenv("ZUFUZZ_EXPECT_FINGERPRINT", unset = NA)
  on.exit(
    if (is.na(old)) Sys.unsetenv("ZUFUZZ_EXPECT_FINGERPRINT") else Sys.setenv(ZUFUZZ_EXPECT_FINGERPRINT = old),
    add = TRUE
  )
  Sys.unsetenv("ZUFUZZ_EXPECT_FINGERPRINT")
  expect_null(expected_fingerprint())
  Sys.setenv(ZUFUZZ_EXPECT_FINGERPRINT = "abc123")
  expect_identical(expected_fingerprint(), "abc123")
})

test_that("a non-matching error is reported as normal, not as a finding", {
  old <- Sys.getenv("ZUFUZZ_EXPECT_FINGERPRINT", unset = NA)
  on.exit(
    if (is.na(old)) Sys.unsetenv("ZUFUZZ_EXPECT_FINGERPRINT") else Sys.setenv(ZUFUZZ_EXPECT_FINGERPRINT = old),
    add = TRUE
  )

  wanted_target <- function(data) stop("the one we want")
  other_target <- function(data) stop("a completely different problem")

  # Taken from a real invocation rather than computed here: the originating
  # call is part of a fingerprint's identity, so the same stop() raised from a
  # different function is legitimately a different finding.
  Sys.unsetenv("ZUFUZZ_EXPECT_FINGERPRINT")
  wanted <- invoke_target(wanted_target, raw(1))$fingerprint$digest
  expect_true(nzchar(wanted))

  Sys.setenv(ZUFUZZ_EXPECT_FINGERPRINT = wanted)

  # This is what stops a minimizer shrinking one bug into another and calling
  # it progress.
  suppressed <- invoke_target(other_target, raw(1))
  expect_identical(suppressed$kind, "normal")
  expect_true(nzchar(suppressed$suppressed))

  expect_identical(invoke_target(wanted_target, raw(1))$kind, "error")
})

test_that("a traceback starts at the target, not at whatever called zufuzz", {
  deep <- function(data) inner()
  inner <- function() innermost()
  innermost <- function() stop("down here")

  tb <- invoke_target(deep, raw(1))$traceback

  # Frames above zufuzz belong to the harness, testthat or an IDE. Twenty of
  # those in a sidecar bury the one frame anyone wants to see.
  expect_true(length(tb) > 0L)
  expect_true(length(tb) < 10L)
  expect_false(any(grepl("test_that|withCallingHandlers|tryCatch", tb)))
  expect_true(any(grepl("innermost", tb)))
})
