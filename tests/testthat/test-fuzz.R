# Stage 4: fuzz()'s run-once mode.
#
# Run-once is the execution model that needs no engine, works on every
# platform, and *returns*. replay(), coverage reporting and the whole Windows
# story are built on it, so it gets tested directly rather than through them.

corpus_of <- function(...) {
  dir <- tempfile("zufuzz-corpus-")
  dir.create(dir, recursive = TRUE)
  inputs <- list(...)
  for (i in seq_along(inputs)) {
    writeBin(inputs[[i]], file.path(dir, sprintf("input-%02d", i)))
  }
  dir
}

test_that("run-once runs every input and returns", {
  seen <- list()
  target <- function(data) {
    seen[[length(seen) + 1L]] <<- data
    invisible(NULL)
  }
  corpus <- corpus_of(as.raw(1:3), as.raw(4:5))

  result <- fuzz(
    target,
    args = corpus, engine = "none", quiet = TRUE,
    artifact_dir = tempfile()
  )

  expect_s3_class(result, "zufuzz_run")
  expect_identical(result$inputs, 2L)
  expect_length(result$findings, 0L)
  expect_identical(seen[[1L]], as.raw(1:3))
  expect_identical(seen[[2L]], as.raw(4:5))
})

test_that("a single file is an input, and a missing one warns", {
  path <- write_input(as.raw(1:2), tempfile("d-"), "only")
  result <- fuzz(function(data) NULL, args = path, engine = "none", quiet = TRUE, artifact_dir = tempfile())
  expect_identical(result$inputs, 1L)

  expect_warning(
    fuzz(function(data) NULL, args = "no-such-file", engine = "none", quiet = TRUE, artifact_dir = tempfile()),
    "no such input"
  )
})

test_that("engine flags are not treated as inputs", {
  corpus <- corpus_of(as.raw(1))
  result <- fuzz(
    function(data) NULL,
    args = c(corpus, "-max_len=64", "-runs=10"),
    engine = "none", quiet = TRUE, artifact_dir = tempfile()
  )
  expect_identical(result$inputs, 1L)
})

test_that("an escaped error becomes an artifact and a sidecar, and run-once continues", {
  artifacts <- tempfile("zufuzz-art-")
  corpus <- corpus_of(as.raw(c(0x01)), as.raw(c(0x02)), as.raw(c(0x03)))

  target <- function(data) {
    if (data[[1L]] == as.raw(0x02)) stop("the fixture error")
    invisible(NULL)
  }

  result <- suppressMessages(
    fuzz(target, args = corpus, engine = "none", quiet = TRUE, artifact_dir = artifacts)
  )

  # Run-once never kills the process: all three inputs ran.
  expect_identical(result$inputs, 3L)
  expect_length(result$findings, 1L)

  finding <- result$findings[[1L]]
  expect_true(file.exists(finding$artifact))
  expect_identical(readBin(finding$artifact, "raw", 10L), as.raw(0x02))

  sidecar <- read_sidecar(finding$artifact)
  expect_identical(sidecar$fingerprint, finding$fingerprint)
  expect_identical(basename(finding$artifact), sidecar$artifact)
})

test_that("the diagnostic names the finding", {
  artifacts <- tempfile()
  corpus <- corpus_of(as.raw(1))
  expect_message(
    fuzz(function(data) stop("boom"), args = corpus, engine = "none", quiet = TRUE, artifact_dir = artifacts),
    "==zufuzz== Uncaught R error"
  )
})

test_that("before_each runs once per input and is not counted", {
  calls <- 0L
  corpus <- corpus_of(as.raw(1), as.raw(2), as.raw(3))
  fuzz(
    function(data) NULL,
    args = corpus, engine = "none", quiet = TRUE, artifact_dir = tempfile(),
    before_each = function() calls <<- calls + 1L
  )
  expect_identical(calls, 3L)
})

test_that("rng_seed makes a sampling target reproducible", {
  corpus <- corpus_of(as.raw(1), as.raw(2), as.raw(3))
  draws <- function(seed) {
    got <- numeric(0)
    fuzz(
      function(data) got <<- c(got, runif(1)),
      args = corpus, engine = "none", quiet = TRUE,
      artifact_dir = tempfile(), rng_seed = seed
    )
    got
  }

  # Every input starts from the same state, so all three draws match...
  first <- draws(42L)
  expect_identical(first[[1L]], first[[2L]])
  expect_identical(first[[1L]], first[[3L]])
  # ...and the whole run repeats.
  expect_identical(draws(42L), first)
  expect_false(identical(draws(7L)[[1L]], first[[1L]]))
})

test_that("rng_seed leaves the caller's RNG state alone", {
  set.seed(99)
  before <- get(".Random.seed", envir = globalenv())

  corpus <- corpus_of(as.raw(1))
  fuzz(
    function(data) runif(1),
    args = corpus, engine = "none", quiet = TRUE,
    artifact_dir = tempfile(), rng_seed = 1L
  )

  expect_identical(get(".Random.seed", envir = globalenv()), before)
})

test_that("gc_torture is enabled around the target and restored after", {
  corpus <- corpus_of(as.raw(1))
  inside <- NULL

  # zufuzz owns turning it on and putting it back; whether a missing PROTECT
  # then crashes is the target's business, and needs native fixtures that
  # deliberately misbehave (roadmap Stage 10, in the Docker image).
  fuzz(
    function(data) inside <<- gctorture(FALSE) || TRUE,
    args = corpus, engine = "none", quiet = TRUE,
    artifact_dir = tempfile(), gc_torture = TRUE
  )
  expect_true(inside)

  expect_silent(fuzz(
    function(data) NULL,
    args = corpus, engine = "none", quiet = TRUE,
    artifact_dir = tempfile(), gc_torture = 50L
  ))
})

test_that("coverage_out records what the corpus reached", {
  on.exit(uninstrument(), add = TRUE)

  classify <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  instrument("classify")

  out <- tempfile(fileext = ".json")
  corpus <- corpus_of(as.raw(1))
  fuzz(
    function(data) classify(1),
    args = corpus, engine = "none", quiet = TRUE,
    artifact_dir = tempfile(), coverage_out = out
  )

  expect_true(file.exists(out))
  report <- jsonlite::read_json(out, simplifyVector = TRUE)
  expect_identical(report$schema, sidecar_schema_version)
  expect_true(report$summary$reached > 0L)
  expect_true(report$summary$reached < report$summary$sites)
  expect_true(any(report$sites$kind == "if_true" & report$sites$hits > 0L))
  expect_true(any(report$sites$kind == "if_false" & report$sites$hits == 0L))
})

test_that("fuzz() validates its arguments", {
  expect_error(fuzz(42), "must be a function")
  expect_error(fuzz(function() NULL), "must take one argument")
  expect_error(
    fuzz(function(d) NULL, args = character(), engine = "none", before_each = 1),
    "must be a function or NULL"
  )
})

test_that("a nested fuzz() is refused", {
  # Tested against the guard directly. Calling fuzz() from inside a target
  # would be caught by the same handler that catches the target's own errors
  # and reported as a finding, which is correct but tests the wrong thing.
  state$in_fuzz <- TRUE
  on.exit(state$in_fuzz <- FALSE, add = TRUE)
  expect_error(
    fuzz(function(d) NULL, args = character(), engine = "none"),
    "already running"
  )
})

test_that("a nested fuzz() inside a target surfaces as a finding, not a hang", {
  corpus <- corpus_of(as.raw(1))
  result <- suppressMessages(fuzz(
    function(data) fuzz(function(d) NULL, args = character(), engine = "none"),
    args = corpus, engine = "none", quiet = TRUE, artifact_dir = tempfile()
  ))
  expect_length(result$findings, 1L)
})

test_that("the nested marker is cleared even when a run errors", {
  corpus <- corpus_of(as.raw(1))
  try(
    suppressMessages(fuzz(
      function(data) stop("boom"),
      args = corpus, engine = "none", quiet = TRUE, artifact_dir = tempfile()
    )),
    silent = TRUE
  )
  expect_false(isTRUE(state$in_fuzz))
})

test_that("an unavailable engine is refused with a message that says so", {
  skip_if(nzchar(Sys.getenv("__AFL_SHM_ID")), "a supervisor is attached")
  # afl is implemented, so the refusal names what is actually missing: a
  # supervisor. Running the handshake and returning silently would leave a
  # harness that appears to work and tests nothing.
  expect_error(
    fuzz(function(d) NULL, args = character(), engine = "afl"),
    "needs a supervisor"
  )
  expect_error(
    fuzz(function(d) NULL, args = character(), engine = "libfuzzer"),
    "not available"
  )
})

test_that("auto resolves to none when no engine is present", {
  # No supervisor attached, which is the state this package is checked in.
  skip_if(nzchar(Sys.getenv("__AFL_SHM_ID")), "an AFL supervisor is attached")
  expect_identical(resolve_engine("auto"), "none")
})

test_that("auto notices an attached AFL supervisor", {
  old <- Sys.getenv("__AFL_SHM_ID", unset = NA)
  Sys.setenv(`__AFL_SHM_ID` = "12345")
  on.exit(
    if (is.na(old)) Sys.unsetenv("__AFL_SHM_ID") else Sys.setenv(`__AFL_SHM_ID` = old),
    add = TRUE
  )
  # Discovery is by environment, which is how AFL's child protocol announces
  # itself. Stage 6 implements what happens next.
  expect_identical(resolve_engine("auto"), "afl")
})

test_that("a run prints its shape", {
  corpus <- corpus_of(as.raw(1))
  expect_output(
    fuzz(function(data) NULL, args = corpus, engine = "none", artifact_dir = tempfile()),
    "zufuzz run"
  )
})
