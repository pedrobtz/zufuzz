# Stage 3: what a run reached, named exactly.
#
# The roadmap's criterion is that coverage "names exactly the sites a
# deterministic fixture reaches" -- not a count, and not a proportion, because
# either could be right for the wrong reason.

test_that("coverage is empty when nothing is instrumented", {
  on.exit(uninstrument(), add = TRUE)
  uninstrument()
  expect_identical(nrow(coverage_sites()), 0L)
  expect_identical(coverage_reached(), character(0))
  expect_identical(coverage_summary()$sites, 0L)
})

test_that("coverage names exactly the sites a deterministic input reaches", {
  on.exit(uninstrument(), add = TRUE)

  classify <- function(x) {
    if (x > 0) {
      "positive"
    } else {
      "negative"
    }
  }
  instrument("classify")

  counter_reset()
  expect_identical(classify(1), "positive")

  # entry, the block statement holding the if, the true outcome, and the
  # statement inside it. The false outcome and its body must be absent.
  expect_identical(
    coverage_reached(),
    c(
      "classify@entry@",
      "classify@block@2",
      "classify@if_true@2.3",
      "classify@block@2.3.2"
    )
  )

  counter_reset()
  expect_identical(classify(-1), "negative")
  expect_identical(
    coverage_reached(),
    c(
      "classify@entry@",
      "classify@block@2",
      "classify@if_false@2.4",
      "classify@block@2.4.2"
    )
  )

  # Both inputs together reach everything the function has.
  counter_reset()
  classify(1)
  classify(-1)
  summary <- coverage_summary()
  expect_identical(summary$reached, summary$sites)
  expect_identical(summary$proportion, 1)
})

test_that("hit counts reflect how often a site ran", {
  on.exit(uninstrument(), add = TRUE)

  count_up <- function(n) {
    total <- 0
    for (i in seq_len(n)) {
      total <- total + i
    }
    total
  }
  instrument("count_up")

  counter_reset()
  expect_identical(count_up(4), 10)

  sites <- coverage_sites()
  loop <- sites[sites$kind == "loop_body", , drop = FALSE]
  expect_identical(nrow(loop), 1L)
  # Loop trip counts become features for free, which is why the counters hold
  # a count rather than a flag.
  expect_identical(loop$hits, 4L)

  entry <- sites[sites$kind == "entry", , drop = FALSE]
  expect_identical(entry$hits, 1L)
})

test_that("an unreached function contributes sites but no hits", {
  on.exit(uninstrument(), add = TRUE)

  used <- function() "used"
  unused <- function() "unused"
  instrument("used", "unused")

  counter_reset()
  used()

  sites <- coverage_sites()
  expect_true(all(sites$hits[sites[["function"]] == "unused"] == 0L))
  expect_true(all(sites$hits[sites[["function"]] == "used"] > 0L))
  expect_lt(coverage_summary()$proportion, 1)
})

test_that("coverage works with no engine attached", {
  on.exit(uninstrument(), add = TRUE)
  f <- function(x) if (x) "a" else "b"
  instrument("f")

  # The whole point of the run-once path: answerable in a plain session, on
  # Windows, and inside R CMD check.
  expect_identical(counter_sink(), "none")
  expect_false(counter_frozen())

  counter_reset()
  f(TRUE)
  expect_gt(length(coverage_reached()), 0L)
})
