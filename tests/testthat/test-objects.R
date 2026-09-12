# Stage 8: bytes to R objects.
#
# One rule underneath all of it (design section 11): an object is a pure,
# deterministic function of the bytes. No RNG, no clock, no environment. Lose
# that and an engine's mutations stop being structural edits, minimize() stops
# shrinking objects, artifacts stop replaying, and draw() stops matching what
# the campaign saw. Most of this file is that rule, from different angles.

random_bytes <- function(n) as.raw(sample.int(256, n, replace = TRUE) - 1L)

test_that("a spec validates its types", {
  expect_error(r_object(types = "frobnicator"), "unknown type")
  expect_error(r_object(types = character()), "at least one type")
  expect_s3_class(r_object(), "r_object_spec")
  expect_output(print(r_object()), "r_object spec")
})

test_that("the spec bounds what is generated", {
  set.seed(1)
  spec <- r_object(types = "integer", max_len = 5, max_depth = 0)
  for (i in seq_len(50)) {
    obj <- fuzzed_data_provider(random_bytes(64))$consume_object(spec)
    expect_true(is.integer(obj) || is.null(obj))
    expect_lte(length(obj), 5L)
  }
})

test_that("list nesting stops at max_depth", {
  set.seed(2)
  spec <- r_object(types = c("list", "integer"), max_len = 3, max_depth = 2)

  depth_of <- function(x) {
    if (!is.list(x) || !length(x)) {
      return(0L)
    }
    1L + max(vapply(x, depth_of, integer(1)))
  }

  for (i in seq_len(100)) {
    obj <- fuzzed_data_provider(random_bytes(400))$consume_object(spec)
    # Bounded by the spec, not by how the bytes happen to fall -- otherwise a
    # mutator could drive the generator into unbounded recursion.
    expect_lte(depth_of(obj), 3L)
  }
})

# The invariant, stated directly.
test_that("draw() and consume_object() agree, byte for byte", {
  set.seed(3)
  spec <- r_object(max_len = 6, max_depth = 2)
  for (i in seq_len(60)) {
    bytes <- random_bytes(300)
    from_draw <- draw(spec, bytes = bytes)[[1L]]
    attr(from_draw, "zufuzz_bytes") <- NULL
    from_provider <- fuzzed_data_provider(bytes)$consume_object(spec)
    # One implementation, two front doors. A second implementation in R would
    # drift, and the drift would be silent.
    expect_identical(from_draw, from_provider)
  }
})

test_that("generation never errors, for any bytes, at either level", {
  set.seed(4)
  for (validity in c("strict", "nasty")) {
    spec <- r_object(max_len = 8, max_depth = 2, validity = validity)
    for (i in seq_len(200)) {
      bytes <- random_bytes(sample.int(400, 1))
      expect_silent(fuzzed_data_provider(bytes)$consume_object(spec))
    }
  }
})

test_that("strict produces nothing that base constructors would not", {
  set.seed(5)
  spec <- r_object(
    types = c("logical", "integer", "double", "character"),
    max_len = 6, max_depth = 0, validity = "strict"
  )
  for (i in seq_len(200)) {
    obj <- fuzzed_data_provider(random_bytes(200))$consume_object(spec)
    if (is.null(obj) || !length(obj)) {
      next
    }
    expect_false(anyNA(obj))
    if (is.double(obj)) {
      expect_true(all(is.finite(obj)))
    }
  }
})

test_that("nasty reaches NA of every type, and the special doubles", {
  set.seed(6)
  spec <- r_object(max_len = 6, max_depth = 1, validity = "nasty")
  seen <- character(0)
  for (i in seq_len(600)) {
    obj <- fuzzed_data_provider(random_bytes(300))$consume_object(spec)
    flat <- tryCatch(unlist(obj, use.names = FALSE), error = function(e) NULL)
    if (is.null(flat) || !length(flat)) {
      next
    }
    if (is.logical(flat) && anyNA(flat)) seen <- c(seen, "NA_logical")
    if (is.integer(flat) && anyNA(flat)) seen <- c(seen, "NA_integer")
    if (is.character(flat) && anyNA(flat)) seen <- c(seen, "NA_character")
    if (is.double(flat)) {
      if (any(is.nan(flat))) seen <- c(seen, "NaN")
      if (any(is.infinite(flat))) seen <- c(seen, "Inf")
      if (any(is.na(flat) & !is.nan(flat))) seen <- c(seen, "NA_real")
    }
  }
  # These are legal, representable, and the things R code most often forgets;
  # a `nasty` level that never produced them would be `strict` with a longer
  # name.
  expect_true(all(
    c("NA_logical", "NA_integer", "NA_character", "NaN", "Inf", "NA_real") %in% seen
  ))
})

test_that("names are generated, and duplicates and blanks are allowed", {
  set.seed(7)
  spec <- r_object(types = "integer", max_len = 6, max_depth = 0, names = TRUE)
  any_named <- FALSE
  for (i in seq_len(300)) {
    obj <- fuzzed_data_provider(random_bytes(200))$consume_object(spec)
    if (!is.null(names(obj))) {
      any_named <- TRUE
      expect_length(names(obj), length(obj))
    }
  }
  expect_true(any_named)

  unnamed <- r_object(types = "integer", max_len = 6, max_depth = 0, names = FALSE)
  for (i in seq_len(100)) {
    obj <- fuzzed_data_provider(random_bytes(120))$consume_object(unnamed)
    expect_null(names(obj))
  }
})

test_that("the same seed draws the same objects, and different seeds differ", {
  spec <- r_object(max_len = 6, max_depth = 2)
  expect_identical(draw(spec, n = 5, seed = 42), draw(spec, n = 5, seed = 42))
  expect_false(identical(draw(spec, n = 5, seed = 42), draw(spec, n = 5, seed = 43)))
  # Each drawn object comes from its own byte stream.
  xs <- draw(spec, n = 3, seed = 11)
  bytes <- lapply(xs, attr, "zufuzz_bytes")
  expect_false(identical(bytes[[1L]], bytes[[2L]]))
})

test_that("draw() never touches .Random.seed", {
  spec <- r_object(max_len = 6, max_depth = 2)
  set.seed(123)
  before <- get(".Random.seed", envir = globalenv())
  invisible(draw(spec, n = 50, seed = 7))
  # Drawing must not disturb the caller's random stream, or an analysis that
  # happens to draw objects becomes irreproducible.
  expect_identical(get(".Random.seed", envir = globalenv()), before)

  # And without a seed either.
  invisible(draw(spec, n = 3))
  expect_identical(get(".Random.seed", envir = globalenv()), before)
})

test_that("every drawn object carries the bytes that produced it", {
  spec <- r_object(max_len = 4, max_depth = 1)
  for (obj in draw(spec, n = 5, seed = 3)) {
    bytes <- attr(obj, "zufuzz_bytes")
    expect_true(is.raw(bytes))
    expect_gt(length(bytes), 0L)

    # And those bytes reproduce it exactly.
    again <- draw(spec, bytes = bytes)[[1L]]
    expect_identical(attr(again, "zufuzz_bytes"), bytes)
    attr(again, "zufuzz_bytes") <- NULL
    stripped <- obj
    attr(stripped, "zufuzz_bytes") <- NULL
    expect_identical(again, stripped)
  }
})

test_that("as_seed() writes bytes a campaign can start from", {
  spec <- r_object(max_len = 4, max_depth = 1)
  obj <- draw(spec, n = 1, seed = 21)[[1L]]
  corpus <- tempfile("zufuzz-corpus-")

  path <- as_seed(obj, corpus)
  expect_true(file.exists(path))
  # The round trip: explore interactively, keep the interesting shapes, start
  # a campaign from them.
  reloaded <- draw(spec, bytes = readBin(path, "raw", file.info(path)$size))[[1L]]
  attr(reloaded, "zufuzz_bytes") <- NULL
  stripped <- obj
  attr(stripped, "zufuzz_bytes") <- NULL
  expect_identical(reloaded, stripped)
})

test_that("as_seed() refuses an object it cannot account for", {
  expect_error(as_seed(list(1, 2), tempfile()), "did not come from draw")
})

test_that("object_from() renders an artifact back into the object", {
  spec <- r_object(max_len = 4, max_depth = 1)
  bytes <- as.raw(c(3, 141, 59, 26, 53, 58, 97, 93, 23, 84, 62, 64, 33, 83, 27, 95))

  dir <- tempfile("zufuzz-art-")
  dir.create(dir, recursive = TRUE)
  path <- write_artifact(bytes, new_sidecar(bytes, "crash"), dir)

  obj <- object_from(path, spec)
  # Triage inspects a value rather than a hexdump.
  expect_identical(attr(obj, "zufuzz_bytes"), bytes)
  attr(obj, "zufuzz_bytes") <- NULL
  expect_identical(obj, fuzzed_data_provider(bytes)$consume_object(spec))

  expect_error(object_from("no-such-artifact", spec), "no such artifact")
})

test_that("the whole surface works with no engine and nothing instrumented", {
  # This is the point of keeping fdp.c free of any engine dependency: the
  # provider and generator are usable in a plain session, and on Windows.
  expect_identical(counter_sink(), "none")
  spec <- r_object(max_len = 4, max_depth = 1)
  expect_silent(draw(spec, n = 3, seed = 1))
  expect_silent(fuzzed_data_provider(as.raw(1:32))$consume_object(spec))
})

test_that("the same bytes give an identical object in a fresh session", {
  skip_if(is.na(installed_zufuzz_lib()), "zufuzz is not installed")

  bytes_literal <- "as.raw(c(3,141,59,26,53,58,97,93,23,84,62,64,33,83,27,95,2,71,82,81))"
  script <- sprintf("
    lib <- Sys.getenv('ZUFUZZ_TEST_LIB'); if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
    library(zufuzz)
    spec <- r_object(max_len = 4, max_depth = 1)
    obj <- fuzzed_data_provider(%s)$consume_object(spec)
    cat(digest::digest(obj, algo = 'sha1'))
  ", bytes_literal)

  from_child <- run_rscript_expr(script)
  expect_true(nzchar(from_child))

  spec <- r_object(max_len = 4, max_depth = 1)
  here <- digest::digest(
    fuzzed_data_provider(eval(parse(text = bytes_literal)))$consume_object(spec),
    algo = "sha1"
  )
  # A corpus has to mean the same thing in the session that recorded it and
  # the one that replays it.
  expect_identical(from_child, here)
})
