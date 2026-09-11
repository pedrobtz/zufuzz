# Stage 5: what this machine can actually run.
#
# The point is that "why did my campaign not start" is answerable *before* the
# campaign, in one call, with the command that would fix it.

test_that("engines() always reports run-once as available", {
  tbl <- engines()
  expect_s3_class(tbl, "zufuzz_engines")
  expect_true(all(c("engine", "available", "found_at", "hint") %in% names(tbl)))

  none <- tbl[tbl$engine == "none", ]
  expect_true(none$available)
  expect_true(engine_available("none"))
})

test_that("an unknown engine is not available rather than an error", {
  expect_false(engine_available("nosuchengine"))
})

test_that("AFL is unavailable on Windows whatever is installed", {
  skip_if_not(.Platform$OS.type == "windows", "not Windows")
  # The child protocol needs System V shared memory; Rtools has none. Saying
  # "install afl++" on Windows would be advice that cannot work.
  expect_false(engine_available("afl"))
  hint <- engines()[engines()$engine == "afl", "hint"]
  expect_match(hint, "WSL|container")
})

test_that("AFL is located through the option, the env var, then PATH", {
  skip_if_not(.Platform$OS.type == "unix", "unix only")

  fake <- tempfile("fake-afl-")
  writeLines("#!/bin/sh\nexit 0", fake)
  Sys.chmod(fake, "0755")

  withr_option <- options(zufuzz.afl_path = fake)
  on.exit(options(withr_option), add = TRUE)
  found <- locate_engine("afl")
  expect_identical(found$path, fake)
  expect_match(found$how, "option")

  options(zufuzz.afl_path = NULL)
  old <- Sys.getenv("ZUFUZZ_AFL_PATH", unset = NA)
  Sys.setenv(ZUFUZZ_AFL_PATH = fake)
  on.exit(
    if (is.na(old)) Sys.unsetenv("ZUFUZZ_AFL_PATH") else Sys.setenv(ZUFUZZ_AFL_PATH = old),
    add = TRUE
  )
  found <- locate_engine("afl")
  expect_identical(found$path, fake)
  expect_match(found$how, "ZUFUZZ_AFL_PATH")
})

test_that("a path that is set but does not exist is not 'found'", {
  withr_option <- options(zufuzz.afl_path = "/definitely/not/here/afl-fuzz")
  on.exit(options(withr_option), add = TRUE)
  found <- locate_engine("afl")
  expect_true(is.na(found$path) || found$path != "/definitely/not/here/afl-fuzz")
})

test_that("an unavailable engine always carries an install hint", {
  tbl <- engines()
  unavailable <- tbl[!tbl$available, , drop = FALSE]
  # An engine reported as missing with no way to get it would be a dead end.
  expect_true(all(!is.na(unavailable$hint)))
})

test_that("the companion is listed but not probed for", {
  # It cannot be probed for until it exists: R CMD check warns about a
  # requireNamespace() naming an undeclared package.
  row <- engines()[engines()$engine == "libfuzzer", ]
  expect_false(row$available)
  expect_false(is.na(row$hint))

  # The hint is platform-specific on purpose. Telling a Windows user to
  # install the companion would be advice that cannot work -- it does not
  # build under Rtools -- so there the hint points at WSL instead.
  if (.Platform$OS.type == "windows") {
    expect_match(row$hint, "WSL|container")
  } else {
    expect_match(row$hint, "companion")
  }
})

test_that("engines() prints, and says what still works without one", {
  out <- capture.output(print(engines()))
  expect_true(any(grepl("zufuzz engines", out)))
  if (!engine_available("afl")) {
    expect_true(any(grepl("replay|runs inputs once", out)))
  }
})
