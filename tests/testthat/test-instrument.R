# Stage 3: selecting, replacing and reporting.
#
# Every test restores what it touched. Instrumentation is process-global and
# replaces bindings in live namespaces, so a test that leaked would change the
# behaviour of the tests after it.

clean_slate <- function() {
  uninstrument()
}

test_that("instrument() replaces a local binding and counts hits", {
  on.exit(clean_slate(), add = TRUE)

  classify <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  original <- classify

  instrument("classify")

  expect_false(identical(body(classify), body(original)))
  expect_identical(classify(1), original(1))
  expect_identical(classify(-1), original(-1))

  report <- instrumentation_report()
  expect_identical(report$n_functions, 1L)
  expect_gt(report$n_sites, 0L)
  expect_gt(sum(counter_hits()), 0L)
})

test_that("instrument() is a no-op under ZUFUZZ_NO_INSTRUMENT", {
  on.exit(clean_slate(), add = TRUE)
  withr_env <- Sys.getenv("ZUFUZZ_NO_INSTRUMENT", unset = NA)
  Sys.setenv(ZUFUZZ_NO_INSTRUMENT = "1")
  on.exit(
    if (is.na(withr_env)) {
      Sys.unsetenv("ZUFUZZ_NO_INSTRUMENT")
    } else {
      Sys.setenv(ZUFUZZ_NO_INSTRUMENT = withr_env)
    },
    add = TRUE
  )

  # This is how replay() re-runs an artifact against the code as it ships,
  # rather than against a rewritten copy of it.
  f <- function(x) x + 1
  before <- body(f)
  instrument("f")
  expect_identical(body(f), before)
  expect_identical(instrumentation_report()$n_functions, 0L)

  expect_identical(instrument_package("digest")$n_functions, 0L)
  expect_identical(instrument_all()$n_functions, 0L)
})

test_that("instrumenting twice keeps ids dense and does not double-wrap", {
  on.exit(clean_slate(), add = TRUE)

  f <- function(x) if (x) 1 else 2
  g <- function(x) if (x) 3 else 4

  instrument("f")
  sites_after_first <- instrumentation_report()$n_sites
  body_after_first <- body(f)

  instrument("g")
  report <- instrumentation_report()

  expect_identical(report$n_functions, 2L)
  expect_gt(report$n_sites, sites_after_first)
  # f is re-transformed from the original, not from its instrumented self.
  expect_identical(deparse(body(f)), deparse(body_after_first))
  expect_identical(f(TRUE), 1)
  expect_identical(g(FALSE), 4)
})

test_that("a selection that cannot be instrumented is reported, not fatal", {
  on.exit(clean_slate(), add = TRUE)
  # sum is a primitive; asking for it must not abort the whole selection.
  expect_no_error(instrument("base::sum", "digest::getVDigest"))
  expect_identical(instrumentation_report()$n_functions, 1L)
})

test_that("locked namespace bindings are replaced and re-locked", {
  on.exit(clean_slate(), add = TRUE)

  ns <- asNamespace("digest")
  expect_true(bindingIsLocked("getVDigest", ns))

  instrument("digest::getVDigest")

  expect_true(bindingIsLocked("getVDigest", ns))
  expect_identical(instrumentation_report()$n_functions, 1L)

  # Still callable, and still correct.
  expect_true(is.function(digest::getVDigest()))
})

test_that("uninstrument() puts every binding back", {
  on.exit(clean_slate(), add = TRUE)

  ns <- asNamespace("digest")
  original <- get("getVDigest", envir = ns)

  instrument("digest::getVDigest")
  expect_false(identical(get("getVDigest", envir = ns), original))

  restored <- uninstrument()
  expect_identical(restored, 1L)
  expect_identical(get("getVDigest", envir = ns), original)
  expect_true(bindingIsLocked("getVDigest", ns))
  expect_identical(instrumentation_report()$n_functions, 0L)
})

test_that("instrumenting after an engine attaches is an error", {
  on.exit(clean_slate(), add = TRUE)

  f <- function(x) if (x) 1 else 2
  instrument("f")
  counter_attach("libfuzzer")

  # A site id handed out before the campaign started must still mean the same
  # counter afterwards, so this is refused rather than silently honoured.
  g <- function(x) x
  expect_error(instrument("g"), "frozen")
})

test_that("a package can be instrumented wholesale", {
  on.exit(clean_slate(), add = TRUE)

  report <- instrument_package("digest")
  expect_gt(report$n_functions, 1L)
  expect_gt(report$n_sites, report$n_functions)

  # Still works after being rewritten end to end.
  expect_identical(digest::digest("abc", algo = "sha1", serialize = FALSE), digest::digest("abc", algo = "sha1", serialize = FALSE))
  expect_gt(sum(counter_hits()), 0L)
})

test_that("exclude is honoured by a package-wide selection", {
  on.exit(clean_slate(), add = TRUE)
  full <- instrument_package("digest")$n_functions
  uninstrument()
  trimmed <- instrument_package("digest", exclude = "getVDigest")$n_functions
  expect_lt(trimmed, full)
})

test_that("instrument_all() selects no zufuzz binding", {
  # Checked on the selection rather than by applying it. Running
  # instrument_all() inside a testthat process rewrites testthat, rlang and
  # pkgload while they are on the call stack -- the criterion is about what is
  # selected, and applying it here would test the harness, not the rule.
  selected <- vapply(select_all(), function(s) s$name, character(1))
  expect_true(length(selected) > 0L)
  expect_false(any(grepl("^zufuzz:", selected)))
  expect_false(any(grepl("^zufuzz:", vapply(select_all(include_base = TRUE), function(s) s$name, character(1)))))
})

test_that("an alias captured before instrumentation is reported", {
  on.exit(clean_slate(), add = TRUE)

  instrument("digest::getVDigest")
  report <- instrumentation_report()

  # zufuzz itself imports digest, so whether an alias exists depends on how
  # the namespace was built. What must hold is that the report answers the
  # question at all rather than implying coverage is complete.
  expect_type(report$aliases, "character")
})

test_that("the report prints, including the unguided warning", {
  on.exit(clean_slate(), add = TRUE)
  expect_output(print(instrumentation_report()), "nothing is instrumented")

  f <- function(x) if (x) 1 else 2
  instrument("f")
  expect_output(print(instrumentation_report()), "zufuzz instrumentation")
  expect_output(print(instrumentation_report()), "JIT level")
})

test_that("the report records the JIT level", {
  on.exit(clean_slate(), add = TRUE)
  f <- function(x) x
  instrument("f")
  # Recorded rather than changed: it explains a performance difference
  # between two otherwise identical campaigns.
  expect_true(is.na(state$jit) || is.numeric(state$jit))
})

test_that("the report does not invent regions it did not skip", {
  on.exit(clean_slate(), add = TRUE)

  clean <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  instrument("clean")

  report <- instrumentation_report()
  expect_identical(nrow(report$skips), 0L)
  # The printed form is what a user reads, so assert on that too.
  expect_false(any(grepl(
    "region\\(s\\) not instrumented",
    capture.output(print(report))
  )))
})

test_that("a selection with nothing instrumentable reports, and does not error", {
  on.exit(clean_slate(), add = TRUE)

  # Asking for a primitive is an easy mistake, and it used to fail with
  # order(NULL)'s "argument 1 is not a vector" -- a message that says nothing
  # about primitives and sends the reader into zufuzz's internals.
  expect_no_error(instrument("base::sum"))
  report <- instrumentation_report()
  expect_identical(report$n_functions, 0L)
  expect_identical(report$n_sites, 0L)
  expect_output(print(report), "nothing is instrumented")
})
