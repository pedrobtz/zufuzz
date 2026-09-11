# Stage 2: what a selection resolves to, and what it must never resolve to.

test_that("qualified selections resolve through a namespace", {
  ok <- resolve_selection("digest::getVDigest")
  expect_identical(ok$status, "ok")
  expect_identical(ok$source, "namespace")
  expect_true(is.function(ok$fn))

  # ::: reaches internals; both spellings are accepted because the user is
  # naming a binding, not asserting an export.
  expect_identical(resolve_selection("digest:::getVDigest")$status, "ok")
})

test_that("unresolvable selections are reported, not thrown", {
  expect_identical(
    resolve_selection("digest::no_such_function")$reason,
    "no binding 'no_such_function' in 'digest'"
  )
  expect_match(
    resolve_selection("notapackage::f")$reason,
    "is not loaded"
  )
  expect_match(resolve_selection("no_such_local_binding")$reason, "no such binding")
  expect_error(resolve_selection(c("a", "b")), "single string")
})

test_that("what cannot be instrumented is named, not silently dropped", {
  expect_match(resolve_selection("base::sum")$reason, "primitive")

  not_a_function <- 42
  expect_match(resolve_selection("not_a_function")$reason, "not a function")
})

test_that("a local closure resolves from the calling environment", {
  local_fn <- function(x) x + 1
  s <- resolve_selection("local_fn")
  expect_identical(s$status, "ok")
  expect_identical(s$source, "local")
})

# The rule with a reason behind it, so it gets a test of its own at every
# entry point: the provider, the generator and the worker loop all run once
# per input. Instrumenting them would feed the engine's own execution back as
# target coverage, and every input would look like a discovery.
test_that("zufuzz is never selected, by any route", {
  expect_identical(resolve_selection("zufuzz::plan_function")$status, "skipped")
  expect_match(resolve_selection("zufuzz:::walk_expr")$reason, "never instrumented")

  expect_match(select_package("zufuzz")[[1L]]$reason, "never instrumented")

  names_from <- function(sel) vapply(sel, function(s) s$name, character(1))

  all_sel <- select_all()
  expect_false(any(grepl("^zufuzz:", names_from(all_sel))))

  # Even when asked for directly, and even with base packages included.
  expect_false(any(grepl("^zufuzz:", names_from(select_packages("zufuzz")))))
  expect_false(any(grepl("^zufuzz:", names_from(select_all(include_base = TRUE)))))
})

test_that("a package selection covers its namespace and its S3 table", {
  sel <- select_package("digest")
  expect_true(length(sel) > 0L)

  ok <- Filter(function(s) identical(s$status, "ok"), sel)
  expect_true(length(ok) > 0L)
  expect_true(all(grepl("^digest:::", vapply(ok, function(s) s$name, character(1)))))

  # Skips are reported rather than dropped, so a user can see what a
  # package-wide selection did not cover.
  skips <- Filter(function(s) identical(s$status, "skipped"), sel)
  expect_true(is.list(skips))
})

test_that("exclude removes a binding by bare or qualified name", {
  names_of <- function(sel) vapply(sel, function(s) s$name, character(1))

  full <- names_of(select_package("digest"))
  expect_true("digest:::getVDigest" %in% full)

  expect_false("digest:::getVDigest" %in% names_of(select_package("digest", exclude = "getVDigest")))
  expect_false(
    "digest:::getVDigest" %in%
      names_of(select_package("digest", exclude = "digest:::getVDigest"))
  )
})

test_that("base and recommended packages are excluded unless asked for", {
  names_from <- function(sel) vapply(sel, function(s) s$name, character(1))

  default <- names_from(select_all())
  expect_false(any(grepl("^stats:::", default)))
  expect_false(any(grepl("^base:::", default)))
})

test_that("recursive selection resolves a dependency graph once each", {
  deps <- package_dependencies("digest")
  expect_true("digest" %in% deps)
  # A diamond or a cycle must not produce a repeat or an infinite walk.
  expect_identical(anyDuplicated(deps), 0L)
  expect_false("zufuzz" %in% deps)

  sel <- select_packages("digest", recursive = TRUE)
  nms <- vapply(sel, function(s) s$name, character(1))
  expect_identical(anyDuplicated(nms), 0L)
})

test_that("only loaded namespaces are selected", {
  # Selection happens after library(): a namespace that was never loaded has
  # no bindings to replace, so asking for it is a no-op rather than an error.
  expect_identical(length(select_packages("definitelyNotLoaded")), 0L)
})

test_that("a real package plans without error and reports its skips", {
  sel <- select_package("digest")
  plan <- plan_selections(sel)

  expect_s3_class(plan, "zufuzz_plan")
  expect_true(plan$n_sites > 0L)
  expect_identical(plan$version, instrumentation_version)

  sites <- plan_sites(plan)
  expect_identical(sites$id, seq.int(0L, length.out = nrow(sites)))
  expect_true(all(nzchar(sites[["function"]])))

  # Whatever the walk declined to enter is available for
  # instrumentation_report() to show, rather than being invisible.
  expect_true(is.data.frame(plan_skips(plan)))

  expect_identical(plan_digest(plan), plan_digest(plan_selections(select_package("digest"))))
})
