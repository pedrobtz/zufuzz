# Stage 2: probe placement, asserted as exact site maps.
#
# These read as "kind@path", where the path is indices into the function body:
# "2.3" means body[[2]][[3]], and "" is the body itself. Asserting the whole
# map rather than a count is the point -- a rule that moves a probe one node
# is a different instrumentation, and the manifest digest will say so.

# paste0() recycles a zero-length argument to "", so an empty plan would
# render as "@" rather than as nothing. Guard it, or "no sites" and "one
# nameless site" become indistinguishable in every expectation below.
label <- function(kind, path) {
  if (!length(kind)) {
    return(character(0))
  }
  paste0(kind, "@", path)
}

sites_of <- function(fn) {
  p <- plan_function(fn)
  label(p$sites$kind, p$sites$path)
}

cmps_of <- function(fn) {
  p <- plan_function(fn)
  label(p$comparisons$fun, p$comparisons$path)
}

skips_of <- function(fn) {
  plan_function(fn)$skips$reason
}

test_that("a function is probed on entry even with an empty body", {
  expect_identical(sites_of(function() {}), "entry@")
  expect_identical(sites_of(function() NULL), "entry@")
  expect_identical(sites_of(function(x) x), "entry@")
})

test_that("every statement of a block is a site", {
  f <- function() {
    a <- 1
    b <- 2
    a + b
  }
  expect_identical(sites_of(f), c("entry@", "block@2", "block@3", "block@4"))
})

test_that("both outcomes of if are sites, and an absent else is marked", {
  with_else <- function(x) {
    if (x) {
      1
    } else {
      2
    }
  }
  expect_identical(
    sites_of(with_else),
    c("entry@", "block@2", "if_true@2.3", "block@2.3.2", "if_false@2.4", "block@2.4.2")
  )

  # The synthesised branch is planned but has no sub-expression yet; Stage 3
  # creates one that still yields an invisible NULL.
  without_else <- function(x) {
    if (x) 1
  }
  expect_identical(
    sites_of(without_else),
    c("entry@", "block@2", "if_true@2.3", "if_false_absent@2.4")
  )
})

test_that("loop bodies are sites and iterator expressions are not", {
  for_loop <- function(n) {
    for (i in seq_len(n)) {
      n <- n - 1
    }
    n
  }
  expect_identical(
    sites_of(for_loop),
    c("entry@", "block@2", "loop_body@2.4", "block@2.4.2", "block@3")
  )

  while_loop <- function(n) {
    while (n > 0) {
      n <- n - 1
    }
  }
  expect_identical(
    sites_of(while_loop),
    c("entry@", "block@2", "loop_body@2.3", "block@2.3.2")
  )

  repeat_loop <- function() {
    repeat {
      break
    }
  }
  expect_identical(
    sites_of(repeat_loop),
    c("entry@", "block@2", "loop_body@2.2", "block@2.2.2")
  )
})

test_that("the walk descends the right-hand side of a simple assignment", {
  f <- function(x) {
    y <- if (x) 1 else 2
    y
  }
  expect_identical(
    sites_of(f),
    c("entry@", "block@2", "if_true@2.3.3", "if_false@2.3.4", "block@3")
  )
})

test_that("a replacement assignment is not descended into", {
  f <- function(x) {
    names(x) <- if (TRUE) "a" else "b"
    x
  }
  # No if_true/if_false: rewriting through the left-hand call would change
  # which replacement function runs.
  expect_identical(sites_of(f), c("entry@", "block@2", "block@3"))
  expect_true(any(grepl("replacement assignment", skips_of(f))))
})

test_that("nesting composes, and paths stay exact", {
  f <- function(x, y) {
    if (x) {
      for (i in y) {
        if (i) {
          1
        }
      }
    }
  }
  expect_identical(
    sites_of(f),
    c(
      "entry@",
      "block@2",
      "if_true@2.3",
      "block@2.3.2",
      "loop_body@2.3.2.4",
      "block@2.3.2.4.2",
      "if_true@2.3.2.4.2.3",
      "block@2.3.2.4.2.3.2",
      "if_false_absent@2.3.2.4.2.4",
      # The outer if's absent else comes last: it is recorded after its true
      # branch has been walked, not before.
      "if_false_absent@2.4"
    )
  )
})

test_that("paths round-trip to the expression they name", {
  f <- function(x) {
    if (x) {
      "yes"
    } else {
      "no"
    }
  }
  p <- plan_function(f)
  body_expr <- body(f)

  for (i in seq_len(nrow(p$sites))) {
    idx <- path_indices(p$sites$path[[i]])
    node <- body_expr
    for (j in idx) node <- node[[j]]
    # Every planned site must name a real node -- except the absent else,
    # which is the one position Stage 3 creates rather than finds.
    if (p$sites$kind[[i]] != "if_false_absent") {
      expect_false(is.null(node))
    }
  }
})

test_that("comparison sites are found in conditions, not counted as coverage", {
  f <- function(s) {
    if (s == "zufuzz") "yes" else "no"
  }
  expect_identical(cmps_of(f), "==@2.2")
  expect_identical(
    sites_of(f),
    c("entry@", "block@2", "if_true@2.3", "if_false@2.4")
  )
})

test_that("each traced comparison function is recognised", {
  # These bodies are the `if` itself rather than a block, so the condition is
  # at "2" -- one level shallower than in the braced fixtures above. Worth
  # covering both: a braceless body is a different shape for the walk.
  expect_identical(cmps_of(function(s) if (s != "a") 1), "!=@2")
  expect_identical(cmps_of(function(s) if (identical(s, "a")) 1), "identical@2")
  expect_identical(cmps_of(function(s) if (s %in% c("a", "b")) 1), "%in%@2")
  expect_identical(cmps_of(function(s) if (startsWith(s, "a")) 1), "startsWith@2")
  expect_identical(cmps_of(function(s) if (endsWith(s, "a")) 1), "endsWith@2")
})

test_that("several comparisons in one condition are all found", {
  f <- function(a, b) {
    if (a == "x" && b == "y") 1
  }
  expect_identical(cmps_of(f), c("==@2.2.2", "==@2.2.3"))
})

test_that("grepl and regexpr are sites only when fixed = TRUE", {
  expect_identical(cmps_of(function(s) if (grepl("a", s, fixed = TRUE)) 1), "grepl@2")
  # Here the condition is `regexpr(...) > 0`, so the traced call is one level
  # further in, at "2.2".
  expect_identical(cmps_of(function(s) if (regexpr("a", s, fixed = TRUE) > 0) 1), "regexpr@2.2")

  # A regex is not a byte comparison, and forwarding its operands would be a
  # lie about what the target compared.
  expect_identical(cmps_of(function(s) if (grepl("a.*b", s)) 1), character(0))
  expect_identical(cmps_of(function(s) if (grepl("a", s, fixed = FALSE)) 1), character(0))
})

test_that("switch is a comparison site only in its string form", {
  expect_identical(cmps_of(function() if (switch("a", a = TRUE, FALSE)) 1), "switch@2")
  # switch on a number is an index, not a comparison.
  expect_identical(cmps_of(function(i) if (switch(i, TRUE, FALSE)) 1), character(0))
})

test_that("quoted regions are left entirely alone", {
  f <- function() {
    quote(a == b)
  }
  expect_identical(sites_of(f), c("entry@", "block@2"))
  expect_identical(cmps_of(f), character(0))
  expect_true(any(grepl("quote()", skips_of(f), fixed = TRUE)))

  g <- function(x) {
    substitute(x == 1)
  }
  expect_identical(cmps_of(g), character(0))
})

test_that("a nested function literal is reported rather than instrumented", {
  f <- function(xs) {
    lapply(xs, function(x) {
      if (x) 1 else 2
    })
  }
  # The inner if contributes nothing: rewriting inside the literal would
  # change what substitute() sees of the argument it is passed as.
  expect_identical(sites_of(f), c("entry@", "block@2"))
  expect_true(any(grepl("nested function literal", skips_of(f))))
})

test_that("call arguments are never instrumented", {
  f <- function(x) {
    print(if (x) 1 else 2)
  }
  expect_identical(sites_of(f), c("entry@", "block@2"))
})

test_that("primitives and non-functions are refused", {
  expect_error(plan_function(sum), "primitive")
  expect_error(plan_function(42), "must be a function")
})

test_that("a byte-compiled closure plans identically to an interpreted one", {
  f <- function(x) {
    if (x) 1 else 2
  }
  g <- compiler::cmpfun(f)
  expect_identical(sites_of(f), sites_of(g))
  expect_identical(plan_function(f)$body_digest, plan_function(g)$body_digest)
})

test_that("site ids are dense, ordered, and named deterministically", {
  a <- function(x) if (x) 1 else 2
  b <- function() NULL

  plan <- new_plan(list(beta = plan_function(b, "beta"), alpha = plan_function(a, "alpha")))
  sites <- plan_sites(plan)

  # Functions sorted by name, not by the order they were handed over.
  expect_identical(unique(sites[["function"]]), c("alpha", "beta"))
  # Dense from zero, with no gaps, so the AFL edge map cannot collide below
  # 64K sites.
  expect_identical(sites$id, seq.int(0L, length.out = nrow(sites)))
  expect_identical(plan$n_sites, nrow(sites))
})

test_that("the digest is stable, and changes when placement would", {
  f <- function(x) if (x) 1 else 2
  g <- function(x) if (x) 1 else 2
  h <- function(x) if (x) 1 else 3

  plan_f <- plan_selections(list(new_selection("f", f)))
  plan_g <- plan_selections(list(new_selection("f", g)))
  plan_h <- plan_selections(list(new_selection("f", h)))

  expect_identical(plan_digest(plan_f), plan_digest(plan_f))
  # Same body, different environment: the digest is of the plan, not the
  # closure, so a corpus stays comparable across sessions.
  expect_identical(plan_digest(plan_f), plan_digest(plan_g))
  expect_false(identical(plan_digest(plan_f), plan_digest(plan_h)))
})

test_that("a duplicate selection is not a second set of counters", {
  f <- function(x) if (x) 1 else 2
  once <- plan_selections(list(new_selection("f", f)))
  twice <- plan_selections(list(new_selection("f", f), new_selection("f", f)))
  expect_identical(once$n_sites, twice$n_sites)
  expect_identical(plan_digest(once), plan_digest(twice))
})

test_that("a plan prints its shape", {
  f <- function(x) if (x) 1 else 2
  expect_output(print(plan_selections(list(new_selection("f", f)))), "zufuzz plan")
})

# Regression: rbind() with every part NULL does not return NULL. Passing
# `make.row.names = FALSE` alongside nothing else makes it
# `rbind(make.row.names = FALSE)` -- a 1x1 matrix named after the argument --
# so instrumentation_report() claimed "1 region(s) not instrumented" for a
# function with nothing skipped. A report that overstates what it missed is
# worse than no report: it sends people looking for coverage that was never
# lost.
test_that("a plan with nothing skipped reports nothing skipped", {
  clean <- function(x) {
    if (x > 0) "positive" else "negative"
  }
  plan <- plan_selections(list(new_selection("clean", clean)))

  skips <- plan_skips(plan)
  expect_true(is.data.frame(skips))
  expect_identical(nrow(skips), 0L)
  expect_identical(names(skips), c("function", "reason", "path"))
  expect_false("make.row.names" %in% rownames(skips))

  sites <- plan_sites(plan)
  expect_true(is.data.frame(sites))
  expect_identical(nrow(sites), 4L)
})

test_that("an empty plan yields empty frames, not stray rows", {
  empty <- new_plan(list())
  expect_identical(nrow(plan_sites(empty)), 0L)
  expect_identical(nrow(plan_skips(empty)), 0L)
})
