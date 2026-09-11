# Stage 4: the record written beside an artifact.

test_that("artifact names follow libFuzzer's convention", {
  bytes <- as.raw(c(0x7a, 0x66))
  expect_match(artifact_name(bytes), "^crash-[0-9a-f]{40}$")
  expect_match(artifact_name(bytes, "timeout"), "^timeout-[0-9a-f]{40}$")
  # Same bytes, same name, on every engine and every platform.
  expect_identical(artifact_name(bytes), artifact_name(as.raw(c(0x7a, 0x66))))
  expect_false(identical(artifact_name(bytes), artifact_name(as.raw(0x7a))))
})

test_that("a sidecar has every field a reader is entitled to", {
  bytes <- as.raw(1:4)
  fp <- fingerprint_condition(tryCatch(stop("x"), error = function(e) e))
  sc <- new_sidecar(bytes, "crash", fingerprint = fp)

  expect_identical(sidecar_missing_fields(sc), character(0))
  expect_identical(sc$sha1, bytes_digest(bytes))
  expect_identical(sc$length, 4L)
  expect_identical(sc$fingerprint, fp$digest)
  expect_identical(sc$condition$message, "x")
})

test_that("a sidecar names the artifact that is actually on disk", {
  dir <- tempfile("zufuzz-sc-")
  bytes <- as.raw(c(9, 8, 7))
  sc <- new_sidecar(bytes, "crash")
  path <- write_artifact(bytes, sc, dir)

  expect_true(file.exists(path))
  expect_identical(basename(path), sc$artifact)
  expect_identical(readBin(path, "raw", 10L), bytes)

  round_tripped <- read_sidecar(path)
  expect_identical(round_tripped$sha1, sc$sha1)
  expect_identical(sidecar_missing_fields(round_tripped), character(0))
})

# A corpus gets committed, attached to issues and shared. Process environments
# hold credentials. This is the one field that must never be captured.
test_that("no environment variable reaches the sidecar", {
  marker <- "zufuzz-secret-value-do-not-record"
  old <- Sys.getenv("ZUFUZZ_TEST_SECRET", unset = NA)
  Sys.setenv(ZUFUZZ_TEST_SECRET = marker)
  on.exit(
    if (is.na(old)) Sys.unsetenv("ZUFUZZ_TEST_SECRET") else Sys.setenv(ZUFUZZ_TEST_SECRET = old),
    add = TRUE
  )

  dir <- tempfile("zufuzz-sc-")
  bytes <- as.raw(1)
  path <- write_artifact(bytes, new_sidecar(bytes, "crash"), dir)

  json <- paste(readLines(paste0(path, ".json"), warn = FALSE), collapse = "\n")
  expect_false(grepl(marker, json, fixed = TRUE))
  expect_false(grepl("ZUFUZZ_TEST_SECRET", json, fixed = TRUE))
})

test_that("the sidecar records enough to explain a non-reproduction", {
  env <- capture_environment()
  expect_true(nzchar(env$r_version))
  expect_true(nzchar(env$platform))
  expect_true(length(env$lib_paths) >= 1L)
  expect_true("zufuzz" %in% names(env$packages))
})

test_that("environment mismatches are reported, never fatal", {
  recorded <- capture_environment()
  expect_identical(environment_mismatches(recorded), character(0))

  recorded$r_version <- "0.1"
  recorded$packages$zufuzz <- "0.0.0.1"
  notes <- environment_mismatches(recorded)

  # A finding from a different R build is still worth looking at, so this
  # reports rather than refuses.
  expect_true(any(grepl("^r_version:", notes)))
  expect_true(any(grepl("^package zufuzz:", notes)))
  expect_identical(environment_mismatches(NULL), character(0))
})

test_that("a sidecar written without a fingerprint is still well formed", {
  # Native crashes and timeouts have no R condition to fingerprint; the
  # sidecar still has to be readable.
  bytes <- as.raw(1)
  sc <- new_sidecar(bytes, "timeout")
  expect_identical(sidecar_missing_fields(sc), character(0))
  expect_null(sc$fingerprint)

  dir <- tempfile("zufuzz-sc-")
  path <- write_artifact(bytes, sc, dir)
  expect_identical(read_sidecar(path)$kind, "timeout")
})
