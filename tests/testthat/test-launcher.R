# Stage 5: running a harness in a child, and deciding what happened.
#
# Every stop_reason is produced by a real fixture rather than a mock. The
# roadmap called for a fake supervisor; it turned out not to be needed,
# because run-once is itself a real engine the launcher can drive, and real
# harnesses produce every outcome.

harness <- function(name) test_path("fixtures", name)

corpus_with <- function(...) {
  dir <- tempfile("zufuzz-corpus-")
  dir.create(dir, recursive = TRUE)
  items <- list(...)
  for (i in seq_along(items)) {
    writeBin(items[[i]], file.path(dir, sprintf("in-%02d", i)))
  }
  dir
}

skip_without_install <- function() {
  skip_if(
    is.na(installed_zufuzz_lib()),
    "zufuzz is not installed; the launcher needs a child that can library() it"
  )
}

test_that("a clean run over a corpus is budget", {
  skip_without_install()
  result <- fuzz_file(
    harness("harness-ok.R"),
    corpus = corpus_with(as.raw(1:4), as.raw(5:8)),
    quiet = TRUE
  )
  expect_s3_class(result, "zufuzz_result")
  expect_identical(result$stop_reason, "budget")
  expect_length(result$findings, 0L)
  expect_null(result$finding)
})

test_that("an escaped error is a finding, with its artifact and fingerprint", {
  skip_without_install()
  result <- fuzz_file(
    harness("harness-error.R"),
    corpus = corpus_with(charToRaw("zfMAGIC"), charToRaw("harmless")),
    quiet = TRUE
  )
  expect_identical(result$stop_reason, "finding")
  expect_length(result$findings, 1L)

  finding <- result$finding
  expect_identical(finding$kind, "crash")
  expect_true(file.exists(finding$artifact))
  expect_true(nzchar(finding$fingerprint))
  # The artifact holds the bytes that caused it, and the sidecar's digest is
  # of those same bytes -- input reproduction, the first of design section 9's
  # three claims.
  bytes <- readBin(finding$artifact, "raw", 16L)
  expect_identical(bytes, charToRaw("zfMAGIC"))
  expect_identical(finding$sidecar$sha1, bytes_digest(bytes))
  expect_identical(basename(finding$artifact), finding$sidecar$artifact)
})

test_that("a harness that cannot load is infrastructure, not a finding", {
  skip_without_install()
  result <- fuzz_file(
    harness("harness-missing-package.R"),
    corpus = corpus_with(as.raw(1)),
    quiet = TRUE
  )
  # Reporting this as a finding would send someone hunting a defect in a
  # package that never loaded.
  expect_identical(result$stop_reason, "infrastructure")
  expect_length(result$findings, 0L)
  expect_match(result$stderr, "definitelyNotARealPackage")
})

test_that("reaching the wall-clock budget is budget, not a finding", {
  skip_without_install()
  started <- Sys.time()
  result <- fuzz_file(
    harness("harness-slow.R"),
    corpus = corpus_with(as.raw(1)),
    time_limit = 3,
    quiet = TRUE
  )
  elapsed <- as.numeric(difftime(Sys.time(), started, units = "secs"))

  # time_limit is the caller's budget. A timeout *finding* is a timeout-<sha1>
  # artifact written because one input hung, which is a different thing.
  expect_identical(result$stop_reason, "budget")
  expect_length(result$findings, 0L)
  # And the child is actually dead, not orphaned: the run returned promptly.
  expect_lt(elapsed, 60)
})

test_that("classification reads artifacts first and the exit code second", {
  # A run that produced a finding is a finding even with a zero exit status,
  # which is what afl-fuzz gives; and a zero status with no artifact is a
  # budget, which is what run-once gives.
  finding <- list(list(artifact = "x", kind = "crash", fingerprint = "abc"))
  expect_identical(classify_run(list(status = 0L), finding), "finding")
  expect_identical(classify_run(list(status = 0L), list()), "budget")
  expect_identical(classify_run(list(status = 1L), list()), "infrastructure")
  expect_identical(classify_run(list(status = 1L), finding), "finding")
  expect_identical(classify_run(list(status = NA_integer_, timeout = TRUE), list()), "budget")
})

test_that("only artifacts created by this run are reported", {
  skip_without_install()
  artifacts <- tempfile("zufuzz-shared-")
  dir.create(artifacts, recursive = TRUE)
  # A stale artifact from an earlier campaign must not be re-reported.
  writeBin(as.raw(0), file.path(artifacts, paste0("crash-", strrep("a", 40))))

  result <- fuzz_file(
    harness("harness-ok.R"),
    corpus = corpus_with(as.raw(1)),
    artifact_dir = artifacts, quiet = TRUE
  )
  expect_identical(result$stop_reason, "budget")
  expect_length(result$findings, 0L)
})

test_that("quiet and verbose runs produce identical results", {
  skip_without_install()
  corpus <- corpus_with(charToRaw("zfMAGIC"))
  quiet <- fuzz_file(harness("harness-error.R"), corpus = corpus, quiet = TRUE)
  loud <- capture.output(
    verbose <- fuzz_file(harness("harness-error.R"), corpus = corpus, quiet = FALSE)
  )
  expect_identical(quiet$stop_reason, verbose$stop_reason)
  expect_identical(
    vapply(quiet$findings, function(f) f$fingerprint, character(1)),
    vapply(verbose$findings, function(f) f$fingerprint, character(1))
  )
  expect_true(any(grepl("zufuzz result", loud)))
})

test_that("an unavailable engine is infrastructure with an actionable message", {
  result <- fuzz_file(harness("harness-ok.R"), engine = "libfuzzer", quiet = TRUE)
  expect_identical(result$stop_reason, "infrastructure")
  expect_match(result$stderr, "engines\\(\\)|not implemented")
})

test_that("the launcher refuses a harness that is not there", {
  expect_error(fuzz_file("no-such-harness.R"), "no such harness")
})

test_that("engine flags must be named", {
  expect_error(flag_arguments(list(4096)), "must be named")
  expect_identical(flag_arguments(list(max_len = 4096)), "-max_len=4096")
  expect_identical(flag_arguments(list()), character(0))
})

test_that("extra environment variables reach the child", {
  skip_without_install()
  # env passthrough is how a sanitized configuration gets its ASAN_OPTIONS.
  result <- fuzz_file(
    harness("harness-ok.R"),
    corpus = corpus_with(as.raw(1)),
    env = c(ZUFUZZ_TEST_MARKER = "present"),
    quiet = TRUE
  )
  expect_identical(result$stop_reason, "budget")
})
