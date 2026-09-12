# Stage 7: shrinking a finding without changing which finding it is.
#
# The interesting test is not that it shrinks. It is that it *stops* shrinking
# when the bug would change -- which is the one thing neither
# `-minimize_crash` nor `afl-tmin` does, and the whole reason this is written
# in R rather than delegated.

skip_without_install <- function() {
  skip_if(
    is.na(installed_zufuzz_lib()),
    "zufuzz is not installed; each candidate is a fresh process"
  )
}

harness <- function(name) test_path("fixtures", name)

# Produce a real finding the way a campaign would.
make_finding <- function(harness_name, bytes) {
  artifacts <- tempfile("zufuzz-found-")
  input <- write_input(bytes, tempfile("zufuzz-in-"), "seed")
  run_harness(harness(harness_name), input, artifacts)
  found <- list.files(artifacts, pattern = "^crash-[0-9a-f]+$", full.names = TRUE)
  if (!length(found)) NA_character_ else found[[1L]]
}

test_that("runs below three is rejected", {
  h <- harness("harness-reducible.R")
  artifact <- tempfile()
  writeBin(charToRaw("zf"), artifact)
  # Fewer than three leaves no budget to confirm the original, try anything,
  # and reconfirm the result, so the answer would be untrustworthy rather than
  # merely unminimized.
  expect_error(minimize(h, artifact, runs = 2), "at least 3")
  expect_error(minimize(h, artifact, runs = 0), "at least 3")
})

test_that("missing paths are refused", {
  expect_error(minimize("no-such-harness.R", tempfile()), "no such harness")
  h <- tempfile(fileext = ".R")
  writeLines("invisible(NULL)", h)
  expect_error(minimize(h, "no-such-artifact"), "no such artifact")
})

test_that("a finding with no fingerprint is refused, not guessed at", {
  h <- harness("harness-reducible.R")
  dir <- tempfile("zufuzz-nofp-")
  dir.create(dir, recursive = TRUE)
  bytes <- charToRaw("padding zf padding")

  # A timeout has no R condition to fingerprint, so "the same bug" cannot be
  # checked and shrinking it would be shrinking something unidentified.
  sidecar <- new_sidecar(bytes, kind = "timeout")
  path <- write_artifact(bytes, sidecar, dir)

  result <- minimize(h, path, runs = 10)
  expect_s3_class(result, "zufuzz_minimize")
  expect_false(is.na(result$refused))
  expect_match(result$refused, "fingerprint|timeout")
  expect_true(is.na(result$minimized))
})

test_that("an artifact with no sidecar is refused", {
  h <- harness("harness-reducible.R")
  path <- tempfile()
  writeBin(charToRaw("zf"), path)
  result <- minimize(h, path, runs = 10)
  expect_match(result$refused, "no sidecar")
})

test_that("a reducible finding shrinks and reconfirms", {
  skip_without_install()

  # Fails whenever "zf" appears anywhere, so everything around it is
  # removable and a correct reducer converges on the marker itself.
  artifact <- make_finding("harness-reducible.R", charToRaw("aaaaaaaazfbbbbbbbb"))
  expect_false(is.na(artifact))
  original <- read_input(artifact)

  result <- minimize(harness("harness-reducible.R"), artifact, runs = 200)

  expect_true(is.na(result$refused))
  expect_true(file.exists(result$minimized))

  minimized <- read_input(result$minimized)
  expect_lt(length(minimized), length(original))
  expect_true(grepl("zf", rawToChar(minimized), fixed = TRUE))

  # And it still is the same finding, checked rather than assumed.
  again <- replay(harness("harness-reducible.R"), result$minimized)
  expect_identical(again$outcome, "error")
  expect_identical(again$fingerprint, read_sidecar(artifact)$fingerprint)
})

test_that("the original artifact is untouched", {
  skip_without_install()

  artifact <- make_finding("harness-reducible.R", charToRaw("aaaazfbbbb"))
  expect_false(is.na(artifact))
  before <- read_input(artifact)
  before_sidecar <- read_sidecar(artifact)

  minimize(harness("harness-reducible.R"), artifact, runs = 100)

  # Minimizing must never destroy the evidence it started from.
  expect_identical(read_input(artifact), before)
  expect_identical(read_sidecar(artifact)$fingerprint, before_sidecar$fingerprint)
})

# The reason this reducer exists.
test_that("it stops rather than shrink into a different bug", {
  skip_without_install()

  # The fixture raises one error for inputs of 8 bytes or more and a
  # *different* one below that, both triggered by the same marker. A reducer
  # that only asks "does it still fail" sails past the boundary and reports a
  # smaller reproducer for a bug nobody was minimizing.
  artifact <- make_finding("harness-bug-switch.R", charToRaw("aaaaaazfaaaaaa"))
  expect_false(is.na(artifact))
  target_fp <- read_sidecar(artifact)$fingerprint

  result <- minimize(harness("harness-bug-switch.R"), artifact, runs = 300)

  expect_true(is.na(result$refused))
  minimized <- read_input(result$minimized)

  # It may shrink, but not past the point where the error changes.
  expect_gte(length(minimized), 8L)

  again <- replay(harness("harness-bug-switch.R"), result$minimized)
  expect_identical(again$fingerprint, target_fp)
  expect_match(again$condition$message, "long-input defect")
})

test_that("a finding that no longer reproduces is refused", {
  skip_without_install()

  # Build a sidecar claiming a fingerprint the harness will never produce.
  dir <- tempfile("zufuzz-stale-")
  dir.create(dir, recursive = TRUE)
  bytes <- charToRaw("harmless")
  fake <- fingerprint_condition(tryCatch(stop("a bug that is gone"), error = function(e) e))
  path <- write_artifact(bytes, new_sidecar(bytes, "crash", fingerprint = fake), dir)

  result <- minimize(harness("harness-reducible.R"), path, runs = 10)
  # Minimizing something that no longer reproduces would produce a confident
  # answer about nothing.
  expect_match(result$refused, "does not reproduce")
})

test_that("the run budget is respected", {
  skip_without_install()

  artifact <- make_finding("harness-reducible.R", charToRaw("aaaaaaaaaaaazfaaaaaaaaaaaa"))
  expect_false(is.na(artifact))

  result <- minimize(harness("harness-reducible.R"), artifact, runs = 6)
  # Each candidate is a fresh process, so the budget is the real cost control
  # and it has to be honoured even when the input is far from minimal.
  expect_lte(result$stats$runs_used, 6L)
})

test_that("the minimized artifact carries its own sidecar", {
  skip_without_install()

  artifact <- make_finding("harness-reducible.R", charToRaw("aaaazfbbbb"))
  expect_false(is.na(artifact))
  result <- minimize(harness("harness-reducible.R"), artifact, runs = 100)

  sidecar <- read_sidecar(result$minimized)
  expect_false(is.null(sidecar))
  # Same bug, different bytes: the fingerprint carries over, the digest does
  # not.
  expect_identical(sidecar$fingerprint, read_sidecar(artifact)$fingerprint)
  expect_identical(sidecar$sha1, bytes_digest(read_input(result$minimized)))
  expect_identical(sidecar$length, length(read_input(result$minimized)))
})

test_that("a minimize result prints", {
  skip_without_install()
  artifact <- make_finding("harness-reducible.R", charToRaw("aazfbb"))
  expect_false(is.na(artifact))
  result <- minimize(harness("harness-reducible.R"), artifact, runs = 60)
  expect_output(print(result), "zufuzz minimize")

  refused <- new_minimize_result("x", NA_character_, "because", list())
  expect_output(print(refused), "refused")
})
