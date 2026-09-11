# Stage 4: re-running an artifact in a process that has never seen the engine.
#
# These need a genuinely fresh R process, which means an *installed* zufuzz.
# Under `R CMD check` there is one; under `devtools::test()` the package is
# loaded from source and no child can see it, so they skip with a reason.

skip_without_install <- function() {
  skip_if(
    is.na(installed_zufuzz_lib()),
    "zufuzz is not installed; subprocess replay needs an installed copy"
  )
}

harness <- function(name) test_path("fixtures", name)

# Produce a real finding the way a campaign would, and hand back the artifact.
make_finding <- function(harness_name, bytes) {
  artifacts <- tempfile("zufuzz-found-")
  input <- write_input(bytes, tempfile("zufuzz-in-"), "seed")
  run <- run_harness(harness(harness_name), input, artifacts)
  found <- list.files(artifacts, pattern = "^crash-[0-9a-f]+$", full.names = TRUE)
  list(run = run, artifact = if (length(found)) found[[1L]] else NA_character_)
}

test_that("a deterministic finding replays with the same fingerprint", {
  skip_without_install()

  found <- make_finding("harness-error.R", charToRaw("zfMAGIC"))
  expect_false(is.na(found$artifact))

  recorded <- read_sidecar(found$artifact)
  expect_true(nzchar(recorded$fingerprint))

  result <- replay(harness("harness-error.R"), found$artifact)

  expect_s3_class(result, "zufuzz_replay")
  expect_identical(result$outcome, "error")
  # The claim replay() exists to make: a fresh, uninstrumented process fails
  # the same way.
  expect_identical(result$fingerprint, recorded$fingerprint)
  expect_true(result$confirmed)
})

test_that("an input that does not fail is reported as normal", {
  skip_without_install()

  input <- write_input(charToRaw("harmless"), tempfile("zufuzz-in-"), "seed")
  result <- replay(harness("harness-error.R"), input)

  expect_identical(result$outcome, "normal")
  expect_null(result$fingerprint)
  expect_false(result$confirmed)
})

test_that("a history-dependent finding is reported as not confirmed", {
  skip_without_install()

  # The fixture fails only on the second input it sees in a process. Replay
  # runs one input in a fresh process, so the finding must not reproduce --
  # and saying "confirmed" here would send someone hunting a bug that depends
  # on the campaign rather than on the bytes.
  artifacts <- tempfile("zufuzz-hist-")
  corpus <- tempfile("zufuzz-corpus-")
  dir.create(corpus, recursive = TRUE)
  writeBin(as.raw(1), file.path(corpus, "a"))
  writeBin(as.raw(2), file.path(corpus, "b"))

  processx::run(
    rscript_bin(), c("--vanilla", harness("harness-history.R"), corpus),
    env = child_env(ZUFUZZ_ARTIFACT_DIR = artifacts),
    error_on_status = FALSE, timeout = 120
  )
  found <- list.files(artifacts, pattern = "^crash-[0-9a-f]+$", full.names = TRUE)
  skip_if(!length(found), "fixture produced no finding")

  result <- replay(harness("harness-history.R"), found[[1L]])
  expect_identical(result$outcome, "normal")
  expect_false(result$confirmed)
})

test_that("the harness runs uninstrumented by default", {
  skip_without_install()

  out <- run_rscript_expr("
    lib <- Sys.getenv('ZUFUZZ_TEST_LIB'); if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
    library(zufuzz)
    f <- function(x) if (x) 1 else 2
    before <- deparse(body(f))
    instrument('f')
    cat(identical(deparse(body(f)), before))
  ", ZUFUZZ_NO_INSTRUMENT = "1")
  # replay() sets exactly this, so an artifact is re-run against the code as
  # it ships rather than a rewritten copy of it.
  expect_identical(out, "TRUE")
})

test_that("replay refuses paths that are not there", {
  expect_error(replay("no-such-harness.R", tempfile()), "no such harness")
  h <- tempfile(fileext = ".R")
  writeLines("invisible(NULL)", h)
  expect_error(replay(h, "no-such-artifact"), "no such artifact")
})

test_that("the expected-fingerprint gate records only the error it was given", {
  skip_without_install()

  # Two distinct errors, chosen by the first byte. With the gate set to the
  # first, feeding the second must produce no finding at all.
  wanted <- make_finding("harness-two-errors.R", as.raw(0x01))
  expect_false(is.na(wanted$artifact))
  fp <- read_sidecar(wanted$artifact)$fingerprint

  artifacts <- tempfile("zufuzz-gate-")
  other <- write_input(as.raw(0x02), tempfile("zufuzz-in-"), "seed")
  run_harness(
    harness("harness-two-errors.R"), other, artifacts,
    ZUFUZZ_EXPECT_FINGERPRINT = fp
  )
  expect_length(list.files(artifacts, pattern = "^crash-[0-9a-f]+$"), 0L)

  # The same gate, fed the matching error, does record it.
  artifacts2 <- tempfile("zufuzz-gate2-")
  same <- write_input(as.raw(0x01), tempfile("zufuzz-in-"), "seed")
  run_harness(
    harness("harness-two-errors.R"), same, artifacts2,
    ZUFUZZ_EXPECT_FINGERPRINT = fp
  )
  expect_length(list.files(artifacts2, pattern = "^crash-[0-9a-f]+$"), 1L)
})

test_that("a replay prints its outcome", {
  skip_without_install()
  input <- write_input(charToRaw("harmless"), tempfile("zufuzz-in-"), "seed")
  expect_output(print(replay(harness("harness-ok.R"), input)), "zufuzz replay")
})
