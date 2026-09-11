# Instrumentation planning: decide where probes would go, and change nothing.
#
# Stage 3 executes a plan; this file only produces one. Keeping the decision
# separate from the rewrite is what makes the placement rules testable against
# exact expected site maps, and what lets instrumentation_report() explain a
# selection before a campaign commits to it.
#
# All internal: nothing here is exported until Stage 3.

# Bumped whenever placement changes meaning. It is part of the manifest
# digest, so a corpus recorded under one version is recognisably not
# comparable with another.
instrumentation_version <- "1"

# Calls rewritten into comparison wrappers (design section 5). Recorded here,
# forwarded to the engine in Stage 9. `switch` and the regex pair are
# conditional -- see comparison_site_kind().
comparison_functions <- c(
  "==", "!=", "identical", "%in%",
  "startsWith", "endsWith",
  "switch", "grepl", "regexpr"
)

# Expressions whose interiors are never touched, because rewriting inside them
# changes what the program means rather than only what it records.
opaque_functions <- c("quote", "bquote", "substitute", "expression", "Quote")

# -- paths ---------------------------------------------------------------

# A site's address is its path from the function body, as indices into
# successive calls: "3.2" means body[[3]][[2]]. Stored as a string because
# that is what makes an expected site map readable in a test; Stage 3 converts
# it back with path_indices(). "" is the body itself.
path_string <- function(path) paste(path, collapse = ".")

path_indices <- function(path) {
  if (!nzchar(path)) {
    return(integer(0))
  }
  as.integer(strsplit(path, ".", fixed = TRUE)[[1L]])
}

# -- the walk ------------------------------------------------------------

new_walk <- function() {
  list(sites = list(), cmp = list(), skips = list())
}

add_site <- function(acc, kind, path) {
  acc$sites[[length(acc$sites) + 1L]] <- list(
    kind = kind,
    path = path_string(path)
  )
  acc
}

add_cmp <- function(acc, fun, path) {
  acc$cmp[[length(acc$cmp) + 1L]] <- list(
    fun = fun,
    path = path_string(path)
  )
  acc
}

add_skip <- function(acc, reason, path) {
  acc$skips[[length(acc$skips) + 1L]] <- list(
    reason = reason,
    path = path_string(path)
  )
  acc
}

call_head <- function(expr) {
  head <- expr[[1L]]
  if (is.name(head)) as.character(head) else ""
}

# Which comparison sites are real. `==` and friends always qualify; `switch`
# only in its string form, and grepl/regexpr only with a literal fixed = TRUE,
# because those are the cases whose operands can be forwarded as bytes. When
# it cannot be decided statically, it is not a site: a false negative costs
# some feedback, a false positive would rewrite a call that means something
# else.
comparison_site_kind <- function(expr, fun) {
  if (fun %in% c("==", "!=", "identical", "%in%", "startsWith", "endsWith")) {
    return(fun)
  }
  args <- as.list(expr)[-1L]
  if (fun == "switch") {
    if (length(args) >= 1L && is.character(args[[1L]])) {
      return("switch")
    }
    # A switch on a variable is decided at Stage 3 from the arm names; a
    # switch on a number is an index, not a comparison.
    return(NA_character_)
  }
  if (fun %in% c("grepl", "regexpr")) {
    fixed <- args[["fixed"]]
    if (!is.null(fixed) && isTRUE(fixed)) {
      return(fun)
    }
    return(NA_character_)
  }
  NA_character_
}

# Conditions are entered only to find comparisons: no coverage probe is ever
# placed inside one, because evaluating a condition twice or changing what it
# returns would change the program.
scan_comparisons <- function(expr, path, acc) {
  if (!is.call(expr)) {
    return(acc)
  }
  fun <- call_head(expr)

  if (fun %in% opaque_functions) {
    return(add_skip(acc, paste0("not descended: ", fun, "()"), path))
  }
  if (fun == "function") {
    return(add_skip(acc, "not descended: nested function literal", path))
  }

  if (fun %in% comparison_functions) {
    kind <- comparison_site_kind(expr, fun)
    if (!is.na(kind)) {
      acc <- add_cmp(acc, kind, path)
    }
  }

  for (i in seq_len(length(expr) - 1L)) {
    acc <- scan_comparisons(expr[[i + 1L]], c(path, i + 1L), acc)
  }
  acc
}

# The placement rules of design section 5, in one pre-order walk. Pre-order is
# what makes site ids a function of the AST rather than of the traversal.
walk_expr <- function(expr, path, acc) {
  if (!is.call(expr)) {
    return(acc)
  }
  fun <- call_head(expr)

  if (fun %in% opaque_functions) {
    return(add_skip(acc, paste0("not instrumented: ", fun, "()"), path))
  }

  # A function literal inside a body is left alone. Rewriting it would change
  # what substitute() sees of the argument it is usually passed as, and the
  # closure it creates is not the binding we replaced. Reported so a
  # closure-heavy package's uninstrumented regions are visible rather than
  # silent.
  if (fun == "function") {
    return(add_skip(acc, "not instrumented: nested function literal", path))
  }

  if (fun == "{") {
    for (i in seq_len(length(expr) - 1L)) {
      stmt <- c(path, i + 1L)
      acc <- add_site(acc, "block", stmt)
      acc <- walk_expr(expr[[i + 1L]], stmt, acc)
    }
    return(acc)
  }

  if (fun == "if") {
    acc <- scan_comparisons(expr[[2L]], c(path, 2L), acc)
    acc <- add_site(acc, "if_true", c(path, 3L))
    acc <- walk_expr(expr[[3L]], c(path, 3L), acc)
    if (length(expr) >= 4L) {
      acc <- add_site(acc, "if_false", c(path, 4L))
      acc <- walk_expr(expr[[4L]], c(path, 4L), acc)
    } else {
      # Stage 3 synthesises the missing else so both outcomes are observable.
      # The synthesised branch must still yield an invisible NULL.
      acc <- add_site(acc, "if_false_absent", c(path, 4L))
    }
    return(acc)
  }

  if (fun == "while") {
    acc <- scan_comparisons(expr[[2L]], c(path, 2L), acc)
    acc <- add_site(acc, "loop_body", c(path, 3L))
    return(walk_expr(expr[[3L]], c(path, 3L), acc))
  }

  if (fun == "repeat") {
    acc <- add_site(acc, "loop_body", c(path, 2L))
    return(walk_expr(expr[[2L]], c(path, 2L), acc))
  }

  if (fun == "for") {
    # The iterator expression is evaluated once, before the loop, and is not
    # descended into: it is an ordinary call argument.
    acc <- add_site(acc, "loop_body", c(path, 4L))
    return(walk_expr(expr[[4L]], c(path, 4L), acc))
  }

  if (fun %in% c("<-", "=", "<<-") && length(expr) >= 3L) {
    # Only a plain symbol target. A replacement assignment -- names(x) <- v --
    # is a call on the left, and rewriting through it would change which
    # replacement function runs.
    if (is.name(expr[[2L]])) {
      return(walk_expr(expr[[3L]], c(path, 3L), acc))
    }
    return(add_skip(acc, "not descended: replacement assignment", path))
  }

  # Anything else is an ordinary call. Its arguments are left intact, because
  # rewriting one changes what substitute() sees -- but they are still read,
  # so that a function literal passed to lapply() and friends is reported as
  # an uninstrumented region rather than silently contributing nothing. For
  # closure-heavy code that is the difference between thin coverage you can
  # explain and thin coverage you cannot.
  note_function_literals(expr, path, acc)
}

note_function_literals <- function(expr, path, acc) {
  if (!is.call(expr)) {
    return(acc)
  }
  fun <- call_head(expr)
  if (fun %in% opaque_functions) {
    return(acc)
  }
  if (fun == "function") {
    return(add_skip(acc, "not instrumented: nested function literal", path))
  }
  for (i in seq_len(length(expr) - 1L)) {
    acc <- note_function_literals(expr[[i + 1L]], c(path, i + 1L), acc)
  }
  acc
}

# -- plans ---------------------------------------------------------------

#' Plan the instrumentation of one closure
#'
#' Produces the site map without touching the function. `body()` is used
#' rather than the bytecode, so a byte-compiled closure plans identically to
#' an interpreted one.
#'
#' @return A `zufuzz_function_plan`.
#' @noRd
plan_function <- function(fn, name = "<anonymous>") {
  if (!is.function(fn)) {
    stop("zufuzz: `fn` must be a function", call. = FALSE)
  }
  if (is.primitive(fn)) {
    stop("zufuzz: primitives have no R body to instrument", call. = FALSE)
  }

  body_expr <- body(fn)
  acc <- new_walk()

  # Function entry always gets a probe, so that being called at all is
  # distinguishable from taking any particular route through the body.
  acc <- add_site(acc, "entry", integer(0))
  acc <- walk_expr(body_expr, integer(0), acc)

  structure(
    list(
      name = name,
      sites = rows_to_df(acc$sites, c("kind", "path")),
      comparisons = rows_to_df(acc$cmp, c("fun", "path")),
      skips = rows_to_df(acc$skips, c("reason", "path")),
      body_digest = digest::digest(
        deparse(body_expr),
        algo = "sha1",
        serialize = FALSE
      )
    ),
    class = "zufuzz_function_plan"
  )
}

rows_to_df <- function(rows, cols) {
  cells <- if (!length(rows)) {
    rep(list(character(0)), length(cols))
  } else {
    lapply(cols, function(col) {
      vapply(rows, function(r) as.character(r[[col]]), character(1))
    })
  }
  names(cells) <- cols
  as.data.frame(cells, stringsAsFactors = FALSE, check.names = FALSE)
}

#' Assemble a whole-campaign plan from resolved selections
#'
#' Site ids are assigned here, densely and in a deterministic order: functions
#' sorted by name, and within a function the pre-order walk. Dense ids are what
#' keep the AFL edge map collision-free below 64K sites, and determinism is
#' what lets a manifest digest mean anything.
#'
#' @noRd
new_plan <- function(function_plans) {
  function_plans <- function_plans[order(names(function_plans))]

  next_site <- 0L
  next_cmp <- 0L
  for (i in seq_along(function_plans)) {
    p <- function_plans[[i]]
    n <- nrow(p$sites)
    p$sites$id <- if (n) seq.int(next_site, length.out = n) else integer(0)
    p$sites <- p$sites[, c("id", "kind", "path"), drop = FALSE]
    next_site <- next_site + n

    m <- nrow(p$comparisons)
    p$comparisons$id <- if (m) seq.int(next_cmp, length.out = m) else integer(0)
    p$comparisons <- p$comparisons[, c("id", "fun", "path"), drop = FALSE]
    next_cmp <- next_cmp + m

    function_plans[[i]] <- p
  }

  structure(
    list(
      version = instrumentation_version,
      functions = function_plans,
      n_sites = next_site,
      n_comparisons = next_cmp
    ),
    class = "zufuzz_plan"
  )
}

#' Digest of everything that makes a plan mean what it means
#'
#' Recorded in sidecars (Stage 4) so a corpus or a finding can be checked
#' against the instrumentation that produced it, and so `-fork`/`-jobs`
#' children can be checked for agreement with their parent.
#'
#' @noRd
plan_digest <- function(plan) {
  parts <- c(
    plan$version,
    vapply(
      plan$functions,
      function(p) paste(p$name, p$body_digest, nrow(p$sites), sep = ":"),
      character(1)
    )
  )
  digest::digest(paste(parts, collapse = "\n"), algo = "sha1", serialize = FALSE)
}

#' @noRd
plan_sites <- function(plan) {
  if (!length(plan$functions)) {
    return(rows_to_df(list(), c("function", "id", "kind", "path")))
  }
  parts <- lapply(plan$functions, function(p) {
    if (!nrow(p$sites)) {
      return(NULL)
    }
    data.frame(
      `function` = p$name,
      p$sites,
      stringsAsFactors = FALSE,
      check.names = FALSE
    )
  })
  do.call(rbind, c(parts, list(make.row.names = FALSE)))
}

#' @noRd
plan_skips <- function(plan) {
  parts <- lapply(plan$functions, function(p) {
    if (!nrow(p$skips)) {
      return(NULL)
    }
    data.frame(
      `function` = p$name,
      p$skips,
      stringsAsFactors = FALSE,
      check.names = FALSE
    )
  })
  out <- do.call(rbind, c(parts, list(make.row.names = FALSE)))
  if (is.null(out)) rows_to_df(list(), c("function", "reason", "path")) else out
}

#' @export
#' @noRd
print.zufuzz_plan <- function(x, ...) {
  cat(sprintf(
    "<zufuzz plan> %d function(s), %d site(s), %d comparison site(s)\n",
    length(x$functions), x$n_sites, x$n_comparisons
  ))
  cat(sprintf("  version %s, digest %s\n", x$version, substr(plan_digest(x), 1, 12)))
  skips <- plan_skips(x)
  if (nrow(skips)) {
    cat(sprintf("  %d region(s) not instrumented\n", nrow(skips)))
  }
  invisible(x)
}
