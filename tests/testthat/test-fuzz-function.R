# Stage 5: the one-liner over a package function.
#
# `fuzz(pkg::parse, corpus = "corpus")` cannot work -- the target takes raw
# bytes, corpus is positional, and a campaign ends the caller's process. This
# generates the harness that intent implies and runs that.

skip_without_install <- function() {
  skip_if(
    is.na(installed_zufuzz_lib()),
    "zufuzz is not installed; fuzz_function() runs its harness in a child"
  )
}

corpus_with <- function(...) {
  dir <- tempfile("zufuzz-corpus-")
  dir.create(dir, recursive = TRUE)
  items <- list(...)
  for (i in seq_along(items)) {
    writeBin(items[[i]], file.path(dir, sprintf("in-%02d", i)))
  }
  dir
}

test_that("a generic condition class in expect is rejected up front", {
  # Catching `error` would catch the defects the campaign exists to find, so
  # this is refused before anything runs rather than silently hiding results.
  for (cls in c("error", "simpleError", "condition", "simpleCondition")) {
    expect_error(
      fuzz_function(identity, expect = cls),
      "specific condition classes"
    )
  }
  expect_error(fuzz_function(42), "must be a function")
})

test_that("a closure that needs a global is infrastructure, and names it", {
  helper_only_in_globalenv <<- function(x) x
  on.exit(rm("helper_only_in_globalenv", envir = globalenv()), add = TRUE)

  target <- function(text) helper_only_in_globalenv(text)
  environment(target) <- globalenv()

  result <- fuzz_function(target, input = "string")

  # R does not serialize the global environment with a closure, so this would
  # fail in the child as an ordinary error inside the target and be reported
  # as a finding -- sending someone to debug a defect that does not exist.
  expect_identical(result$stop_reason, "infrastructure")
  expect_match(result$stderr, "helper_only_in_globalenv")
})

test_that("globals that live in a package survive serialization", {
  target <- function(text) toupper(text)
  expect_identical(globals_lost_by_serialization(target), character(0))
})

test_that("a namespace function travels by name, not by value", {
  spec <- describe_target(digest::getVDigest, quote(digest::getVDigest))
  expect_identical(spec$kind, "name")
  expect_identical(spec$pkg, "digest")
  expect_identical(spec$name, "getVDigest")
})

test_that("the generated harness is a real harness", {
  spec <- list(kind = "name", pkg = "digest", name = "getVDigest")
  src <- harness_source(spec, input = "raw", expect = character(), instrument = NULL)
  txt <- paste(src, collapse = "\n")

  expect_true(any(grepl("^library\\(zufuzz\\)$", src)))
  expect_true(grepl('asNamespace("digest")', txt, fixed = TRUE))
  expect_true(grepl('instrument_package("digest")', txt, fixed = TRUE))
  expect_true(grepl("fuzz(test_one_input", txt, fixed = TRUE))
  # It has to parse, or "promote it into a real harness" is a false promise.
  expect_silent(parse(text = txt))
})

test_that("expect is caught around the call and nothing else", {
  spec <- list(kind = "object", path = "/tmp/x.rds")
  src <- harness_source(spec, input = "string", expect = "pair_error", instrument = NULL)
  txt <- paste(src, collapse = "\n")

  expect_true(grepl("tryCatch(target_fn(value)", txt, fixed = TRUE))
  expect_true(grepl("pair_error", txt, fixed = TRUE))
  expect_silent(parse(text = txt))

  # Without expect there is no handler at all: an escaped error is the point.
  plain <- paste(harness_source(spec, "raw", character(), NULL), collapse = "\n")
  expect_false(grepl("tryCatch", plain, fixed = TRUE))
})

test_that("the string adapter never errors, whatever the bytes", {
  decode <- eval(parse(text = paste0(
    "function(data) {\n",
    paste(input_adapter_lines("string"), collapse = "\n"),
    "\n  value\n}"
  )))

  # Fuzzed bytes are arbitrary; a harness that errors while *decoding* reports
  # a defect in the adapter rather than in the target.
  expect_silent(decode(as.raw(c(0x00, 0xff, 0xfe, 0x41))))
  expect_silent(decode(raw(0)))
  expect_type(decode(charToRaw("plain text")), "character")
  expect_identical(decode(charToRaw("plain text")), "plain text")
})

test_that("a planted defect is found and an expected rejection is not", {
  skip_without_install()

  # Stand-in for a package function: `pair_error` is its documented rejection,
  # and there is one planted defect that is not in that class.
  source(test_path("fixtures", "pkg-target.R"), local = TRUE)

  result <- fuzz_function(
    parse_pair,
    corpus = corpus_with(charToRaw(""), charToRaw("a=b"), charToRaw("!boom")),
    input = "string",
    expect = "pair_error",
    quiet = TRUE
  )

  expect_identical(result$stop_reason, "finding")
  expect_length(result$findings, 1L)
  expect_match(result$finding$sidecar$condition$message, "planted defect")
  # The empty input raises pair_error, which is expected and therefore not a
  # finding; exactly one artifact means it was not reported.
  expect_identical(result$finding$kind, "crash")
})

test_that("without expect, the documented rejection is reported too", {
  skip_without_install()
  source(test_path("fixtures", "pkg-target.R"), local = TRUE)

  result <- fuzz_function(
    parse_pair,
    corpus = corpus_with(charToRaw("")),
    input = "string",
    quiet = TRUE
  )
  # Nothing is expected, so everything that escapes is a finding. This is what
  # `expect` exists to narrow.
  expect_identical(result$stop_reason, "finding")
})

test_that("the harness path is reported so it can be promoted", {
  skip_without_install()
  source(test_path("fixtures", "pkg-target.R"), local = TRUE)

  out <- tempfile("promoted-", fileext = ".R")
  result <- fuzz_function(
    parse_pair,
    corpus = corpus_with(charToRaw("a=b")),
    input = "string", expect = "pair_error",
    harness_out = out, quiet = TRUE
  )
  expect_identical(result$harness, out)
  expect_true(file.exists(out))
  expect_silent(parse(out))
})
