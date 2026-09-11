# Executing a plan: rewrite a closure's body so it records where it went.
#
# The walk here mirrors walk_expr() in plan.R node for node, in the same
# pre-order, so the ids it assigns are the ids the plan promised. That is not
# left to trust: transform_function() compares the sites it emitted against
# the plan's and refuses if they differ. A silent divergence between the two
# walks would mean a site map that describes coverage the target never had.
#
# The transformation must be invisible to the program. Every construct below
# preserves value, visibility, laziness, evaluation order and count, error
# propagation, return/break/next, and on.exit.

# `.Call` and the routine are embedded as objects, not names, so neither is
# looked up at run time and neither can be shadowed by the target. Verified
# by a test that defines a hostile `.Call` in scope.
probe_call <- function(id) {
  as.call(list(.Call, C_zufuzz_probe, as.integer(id)))
}

# The value of `{ a; b }` is b, and so is its visibility, so prefixing a probe
# changes neither.
braced <- function(...) {
  as.call(c(list(as.name("{")), list(...)))
}

# `if (x) y` yields an *invisible* NULL when x is false. A synthesised else
# has to reproduce that exactly, or instrumenting a function changes what it
# prints at the console. `invisible` is embedded as an object for the same
# reason `.Call` is.
invisible_null <- function() {
  as.call(list(invisible, NULL))
}

new_tx <- function(first_id) {
  list(id = as.integer(first_id), sites = list())
}

tx_site <- function(st, kind, path) {
  st$sites[[length(st$sites) + 1L]] <- list(
    kind = kind,
    path = path_string(path),
    id = st$id
  )
  st$id <- st$id + 1L
  st
}

transform_expr <- function(expr, path, st) {
  if (!is.call(expr)) {
    return(list(expr = expr, st = st))
  }
  fun <- call_head(expr)

  # Left exactly as found, for the reasons plan.R records as skips.
  if (fun %in% opaque_functions || fun == "function") {
    return(list(expr = expr, st = st))
  }

  if (fun == "{") {
    parts <- list(as.name("{"))
    for (i in seq_len(length(expr) - 1L)) {
      stmt_path <- c(path, i + 1L)
      id <- st$id
      st <- tx_site(st, "block", stmt_path)
      out <- transform_expr(expr[[i + 1L]], stmt_path, st)
      st <- out$st
      parts <- c(parts, list(probe_call(id), out$expr))
    }
    return(list(expr = as.call(parts), st = st))
  }

  if (fun == "if") {
    # The condition is not touched here. Stage 9 rewrites comparison calls
    # inside it; until then, entering a condition at all would risk changing
    # how many times it is evaluated.
    cond <- expr[[2L]]

    id_true <- st$id
    st <- tx_site(st, "if_true", c(path, 3L))
    yes <- transform_expr(expr[[3L]], c(path, 3L), st)
    st <- yes$st

    if (length(expr) >= 4L) {
      id_false <- st$id
      st <- tx_site(st, "if_false", c(path, 4L))
      no <- transform_expr(expr[[4L]], c(path, 4L), st)
      st <- no$st
      no_expr <- braced(probe_call(id_false), no$expr)
    } else {
      id_false <- st$id
      st <- tx_site(st, "if_false_absent", c(path, 4L))
      no_expr <- braced(probe_call(id_false), invisible_null())
    }

    out <- as.call(list(
      as.name("if"), cond,
      braced(probe_call(id_true), yes$expr),
      no_expr
    ))
    return(list(expr = out, st = st))
  }

  if (fun == "while") {
    id <- st$id
    st <- tx_site(st, "loop_body", c(path, 3L))
    body_out <- transform_expr(expr[[3L]], c(path, 3L), st)
    st <- body_out$st
    out <- as.call(list(
      as.name("while"), expr[[2L]],
      braced(probe_call(id), body_out$expr)
    ))
    return(list(expr = out, st = st))
  }

  if (fun == "repeat") {
    id <- st$id
    st <- tx_site(st, "loop_body", c(path, 2L))
    body_out <- transform_expr(expr[[2L]], c(path, 2L), st)
    st <- body_out$st
    out <- as.call(list(
      as.name("repeat"),
      braced(probe_call(id), body_out$expr)
    ))
    return(list(expr = out, st = st))
  }

  if (fun == "for") {
    id <- st$id
    st <- tx_site(st, "loop_body", c(path, 4L))
    body_out <- transform_expr(expr[[4L]], c(path, 4L), st)
    st <- body_out$st
    out <- as.call(list(
      as.name("for"), expr[[2L]], expr[[3L]],
      braced(probe_call(id), body_out$expr)
    ))
    return(list(expr = out, st = st))
  }

  if (fun %in% c("<-", "=", "<<-") && length(expr) >= 3L && is.name(expr[[2L]])) {
    rhs <- transform_expr(expr[[3L]], c(path, 3L), st)
    # Rebuilt with as.call() rather than `out[[3L]] <- rhs$expr`. Assigning
    # NULL into a call *removes* that element, so `x <- NULL` would silently
    # become `` `<-`(x) `` -- a one-argument assignment that deparses
    # identically and fails only when evaluated. as.call() on a list keeps a
    # NULL element as an element.
    out <- as.call(list(expr[[1L]], expr[[2L]], rhs$expr))
    return(list(expr = out, st = rhs$st))
  }

  # An ordinary call: arguments are left intact, because rewriting one changes
  # what substitute() sees.
  list(expr = expr, st = st)
}

transform_body <- function(body_expr, st) {
  id <- st$id
  st <- tx_site(st, "entry", integer(0))
  out <- transform_expr(body_expr, integer(0), st)
  list(expr = braced(probe_call(id), out$expr), st = out$st)
}

#' Rewrite one closure according to its plan
#'
#' @param fn The closure. Its `body()` is used, so a byte-compiled closure
#'   transforms identically to an interpreted one; assigning a new body drops
#'   the stale bytecode and R's JIT recompiles on its own.
#' @param fn_plan The `zufuzz_function_plan` for `fn`.
#' @param first_id The site id this function's counters start at.
#' @return The transformed closure.
#' @noRd
transform_function <- function(fn, fn_plan, first_id) {
  out <- transform_body(body(fn), new_tx(first_id))

  # Compared as labels rather than as data frames: identical() on a data
  # frame also compares row.names, which differ between a freshly built frame
  # and a subset of one, and would fail for a reason that has nothing to do
  # with placement.
  emitted <- vapply(
    out$st$sites,
    function(s) paste0(s$kind, "@", s$path),
    character(1)
  )
  expected <- if (nrow(fn_plan$sites)) {
    paste0(fn_plan$sites$kind, "@", fn_plan$sites$path)
  } else {
    character(0)
  }
  if (!identical(emitted, expected)) {
    stop(
      "zufuzz: the transformer and the planner disagree about ",
      fn_plan$name,
      "; this is a zufuzz bug, not a problem with the target",
      call. = FALSE
    )
  }

  new_fn <- fn
  body(new_fn) <- out$expr

  # Formals and environment survive `body<-`. Other attributes are restored
  # by hand, minus srcref: a source reference that no longer describes the
  # body is worse than none, and it would make deparse() lie.
  attrs <- attributes(fn)
  attrs[["srcref"]] <- NULL
  if (length(attrs)) {
    attributes(new_fn) <- attrs
  }

  new_fn
}
