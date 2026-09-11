# Stage 3: the transformation must be invisible to the program.
#
# Every test here compares an instrumented closure against the original on
# something a caller could notice. A fuzzer that changes its target's
# behaviour reports bugs that do not exist, which is worse than reporting
# none, so this file is the stage's real deliverable.

instrumented_copy <- function(fn, sites = 512L) {
  counter_thaw()
  counter_alloc(sites)
  counter_reset()
  transform_function(fn, plan_function(fn, "f"), 0L)
}

# Value *and* visibility: R programs observe both, and `{ }` wrapping is
# exactly where visibility is easy to lose.
expect_same <- function(original, instrumented, ...) {
  a <- withVisible(original(...))
  b <- withVisible(instrumented(...))
  expect_identical(b$value, a$value)
  expect_identical(b$visible, a$visible)
}

teardown_counters <- function() {
  counter_thaw()
  counter_alloc(0)
}

test_that("values and visibility survive, including invisible results", {
  on.exit(teardown_counters(), add = TRUE)

  f <- function(x) x * 2
  expect_same(f, instrumented_copy(f), 21)

  g <- function(x) invisible(x)
  expect_same(g, instrumented_copy(g), 1)

  # `if` with no else yields an *invisible* NULL. The synthesised else has to
  # reproduce that, or instrumenting changes what prints at the console.
  h <- function(x) {
    if (x) "yes"
  }
  expect_same(h, instrumented_copy(h), TRUE)
  expect_same(h, instrumented_copy(h), FALSE)

  ih <- instrumented_copy(h)
  expect_null(ih(FALSE))
  expect_false(withVisible(ih(FALSE))$visible)
})

test_that("assignment still returns its value invisibly", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function() {
    x <- 42
  }
  expect_same(f, instrumented_copy(f))
})

# Regression: rebuilding an assignment with `out[[3L]] <- rhs` *removes* the
# element when rhs is NULL, turning `x <- NULL` into a one-argument
# `` `<-`(x) ``. It deparses identically and fails only when evaluated, so it
# was invisible until a real package (`testthat:::o_apply`, whose first line
# is `x <- NULL`) blew up. `x <- NULL` is far too common for this to be an
# edge case.
test_that("assigning NULL survives the rewrite", {
  on.exit(teardown_counters(), add = TRUE)

  f <- function() {
    x <- NULL
    x
  }
  g <- instrumented_copy(f)
  expect_null(g())

  body_expr <- body(g)
  assignments <- Filter(
    function(e) is.call(e) && identical(e[[1L]], as.name("<-")),
    as.list(body_expr[[3L]])
  )
  # Arity, not deparse: the corrupted form prints the same as the correct one.
  expect_true(all(vapply(assignments, length, integer(1)) == 3L))

  h <- function(flag) {
    value <- NULL
    if (flag) {
      value <- NULL
    }
    value
  }
  ih <- instrumented_copy(h)
  expect_null(ih(TRUE))
  expect_null(ih(FALSE))
})

test_that("side effects happen once, in order", {
  on.exit(teardown_counters(), add = TRUE)

  log <- character(0)
  note <- function(x) {
    log <<- c(log, x)
    x
  }
  f <- function() {
    note("a")
    note("b")
    note("c")
  }

  log <- character(0)
  f()
  from_original <- log

  log <- character(0)
  instrumented_copy(f)()
  expect_identical(log, from_original)
  expect_identical(log, c("a", "b", "c"))
})

test_that("laziness is preserved: an unused argument is never forced", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(used, unused) {
    used
  }
  g <- instrumented_copy(f)
  # Would error if the promise were forced by the rewrite.
  expect_identical(g(1, stop("forced!")), 1)
})

test_that("missing arguments stay missing", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(x, y) {
    missing(y)
  }
  expect_true(instrumented_copy(f)(1))
  expect_false(instrumented_copy(f)(1, 2))
})

test_that("errors propagate with their condition intact", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function() {
    stop(structure(
      class = c("my_error", "error", "condition"),
      list(message = "boom", call = NULL)
    ))
  }
  g <- instrumented_copy(f)
  expect_error(g(), class = "my_error")
  expect_error(g(), "boom")
})

test_that("return, break and next still transfer control", {
  on.exit(teardown_counters(), add = TRUE)

  early <- function(x) {
    if (x) {
      return("early")
    }
    "late"
  }
  expect_identical(instrumented_copy(early)(TRUE), "early")
  expect_identical(instrumented_copy(early)(FALSE), "late")

  with_break <- function() {
    total <- 0
    for (i in 1:10) {
      if (i > 3) {
        break
      }
      total <- total + i
    }
    total
  }
  expect_identical(instrumented_copy(with_break)(), 6)

  with_next <- function() {
    total <- 0
    for (i in 1:5) {
      if (i %% 2 == 0) {
        next
      }
      total <- total + i
    }
    total
  }
  expect_identical(instrumented_copy(with_next)(), 9)

  with_repeat <- function() {
    i <- 0
    repeat {
      i <- i + 1
      if (i >= 3) {
        break
      }
    }
    i
  }
  expect_identical(instrumented_copy(with_repeat)(), 3)
})

test_that("on.exit still runs, in order, including on error", {
  on.exit(teardown_counters(), add = TRUE)

  log <- character(0)
  f <- function(fail) {
    on.exit(log <<- c(log, "first"), add = TRUE)
    on.exit(log <<- c(log, "second"), add = TRUE)
    if (fail) {
      stop("boom")
    }
    "ok"
  }

  log <- character(0)
  expect_identical(instrumented_copy(f)(FALSE), "ok")
  expect_identical(log, c("first", "second"))

  log <- character(0)
  expect_error(instrumented_copy(f)(TRUE), "boom")
  expect_identical(log, c("first", "second"))
})

test_that("formals, environment and attributes survive", {
  on.exit(teardown_counters(), add = TRUE)

  make <- function(k) {
    f <- function(x, y = 10, ...) x + y + k
    attr(f, "zufuzz_marker") <- "kept"
    f
  }
  f <- make(5)
  g <- instrumented_copy(f)

  expect_identical(formals(g), formals(f))
  expect_identical(environment(g), environment(f))
  expect_identical(attr(g, "zufuzz_marker"), "kept")
  expect_identical(g(1), f(1))
  # Default arguments are evaluated in the function's own frame, so this only
  # works if the environment really was preserved.
  expect_identical(g(1, 2), 8)
})

test_that("a byte-compiled closure transforms identically", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  compiled <- compiler::cmpfun(f)

  from_source <- instrumented_copy(f)
  from_bytecode <- instrumented_copy(compiled)

  expect_identical(deparse(body(from_bytecode)), deparse(body(from_source)))
  expect_identical(from_bytecode(1), "positive")
  expect_identical(from_bytecode(-1), "negative")
})

test_that("the probe cannot be intercepted by a shadowed .Call", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(x) {
    if (x) "yes" else "no"
  }
  g <- instrumented_copy(f)

  hostile <- function() {
    .Call <- function(...) stop("intercepted")
    invisible <- function(...) stop("intercepted")
    g(TRUE)
  }
  expect_identical(hostile(), "yes")
})

test_that("S3 dispatch still reaches the instrumented method", {
  on.exit(teardown_counters(), add = TRUE)

  describe <- function(x, ...) UseMethod("describe")
  describe.zufuzz_demo <- function(x, ...) {
    if (length(x) > 1L) "many" else "one"
  }

  counter_thaw()
  counter_alloc(64)
  counter_reset()
  instrumented <- transform_function(
    describe.zufuzz_demo,
    plan_function(describe.zufuzz_demo, "describe.zufuzz_demo"),
    0L
  )
  describe.zufuzz_demo <- instrumented

  obj <- structure(list(1, 2), class = "zufuzz_demo")
  expect_identical(describe(obj), "many")
  expect_gt(sum(counter_hits()), 0L)
})

test_that("the transformer refuses a plan it disagrees with", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(x) if (x) 1 else 2
  g <- function(x) {
    x
  }
  counter_thaw()
  counter_alloc(64)
  # A plan for a different function must not be applied quietly: a site map
  # that describes coverage the target never had is worse than an error.
  expect_error(
    transform_function(f, plan_function(g, "g"), 0L),
    "disagree"
  )
})

test_that("probes fire for the branches actually taken", {
  on.exit(teardown_counters(), add = TRUE)
  f <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  g <- instrumented_copy(f)

  counter_reset()
  g(1)
  taken <- counter_hits()

  counter_reset()
  g(-1)
  other <- counter_hits()

  expect_false(identical(taken, other))
  # Entry and the block are common; the two if outcomes are not.
  expect_gt(sum(taken > 0L), 0L)
  expect_gt(sum(other > 0L), 0L)
})
