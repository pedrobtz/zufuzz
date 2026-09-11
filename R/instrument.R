# Selecting, planning, transforming and replacing -- the public face.
#
# Everything before this file decided what would happen; this is where it
# happens. The order matters and is enforced: instrumentation must be complete
# before an engine attaches, because attaching freezes the counter region and
# a site id handed out beforehand must still mean the same counter after.

# Campaign state. An environment rather than options() because it is state,
# not preference, and because it must not survive into a child process by
# accident.
state <- new.env(parent = emptyenv())

reset_state <- function() {
  state$targets <- list()
  state$skipped <- list()
  state$plan <- NULL
  state$replaced <- list()
  state$jit <- NA_integer_
}
reset_state()

# ZUFUZZ_NO_INSTRUMENT=1 makes every entry point a no-op. replay() sets it, so
# that an artifact is re-run against the code as it actually ships rather than
# against a rewritten copy of it.
instrumentation_disabled <- function() {
  nzchar(Sys.getenv("ZUFUZZ_NO_INSTRUMENT"))
}

#' Instrument selected functions for coverage feedback
#'
#' Rewrites the body of each selected closure so that reaching a branch
#' records a hit, then replaces the binding it came from. The rewrite
#' preserves value, visibility, laziness, evaluation order, error propagation,
#' `return()`/`break`/`next`, and `on.exit()`.
#'
#' Instrumentation must be complete before a campaign starts: attaching an
#' engine freezes the counter region, and a later call is an error rather than
#' a silent no-op.
#'
#' All of these are no-ops when `ZUFUZZ_NO_INSTRUMENT` is set, which is how an
#' artifact is re-run against uninstrumented code.
#'
#' @param ... Selections, as strings: `"pkg::fn"`, `"pkg:::internal"`, or the
#'   name of a function in the calling environment.
#' @param compare Reserved for comparison tracing, which arrives with the
#'   engine that can forward it. Accepted now so harnesses need not change.
#' @return The [instrumentation_report()], invisibly.
#' @export
#' @examples
#' f <- function(x) if (x > 0) "positive" else "negative"
#' instrument("f")
#' f(1)
#' instrumentation_report()
instrument <- function(..., compare = TRUE) {
  specs <- c(...)
  if (instrumentation_disabled() || !length(specs)) {
    return(invisible(instrumentation_report()))
  }
  envir <- parent.frame()
  selections <- lapply(specs, resolve_selection, envir = envir)
  apply_instrumentation(selections)
}

#' @rdname instrument
#' @param pkg Package name.
#' @param exclude Function names to leave alone, bare or qualified.
#' @param recursive Also instrument the package's `Imports` and `Depends`.
#'   This is the analogue of Atheris's `instrument_imports()`.
#' @export
instrument_package <- function(pkg, exclude = character(), recursive = FALSE,
                               compare = TRUE) {
  if (instrumentation_disabled()) {
    return(invisible(instrumentation_report()))
  }
  apply_instrumentation(select_packages(pkg, exclude = exclude, recursive = recursive))
}

#' @rdname instrument
#' @param include_base Also instrument base and recommended packages. Off by
#'   default: the noise and the cost are rarely worth it.
#' @export
instrument_all <- function(exclude = character(), include_base = FALSE,
                           compare = TRUE) {
  if (instrumentation_disabled()) {
    return(invisible(instrumentation_report()))
  }
  apply_instrumentation(select_all(exclude = exclude, include_base = include_base))
}

apply_instrumentation <- function(selections) {
  if (counter_frozen()) {
    stop(
      "zufuzz: the counter region is frozen; instrumentation must be ",
      "complete before a campaign starts",
      call. = FALSE
    )
  }

  # New targets are remembered with the closure as it was *before* any
  # rewriting. Re-resolving later would find the instrumented copy and
  # instrument it again.
  for (s in selections) {
    if (!identical(s$status, "ok")) {
      state$skipped[[s$name]] <- s
      next
    }
    if (is.null(state$targets[[s$name]])) {
      state$targets[[s$name]] <- s
    }
  }

  # Everything is re-planned and re-transformed from the originals on every
  # call, so ids stay dense and stable no matter how many times instrument()
  # is called before the campaign starts.
  plan <- plan_selections(state$targets)
  counter_alloc(plan$n_sites)

  # The undo record is written as each binding is replaced, not assembled and
  # stored at the end. If transformation fails partway through a package, the
  # bindings already swapped must still be restorable -- otherwise a single
  # bad function leaves the session permanently half-instrumented, with no way
  # back.
  state$plan <- plan
  state$replaced <- list()
  for (fn_plan in plan$functions) {
    target <- state$targets[[fn_plan$name]]
    first_id <- if (nrow(fn_plan$sites)) fn_plan$sites$id[[1L]] else 0L
    instrumented <- transform_function(target$fn, fn_plan, first_id)
    replace_binding(target$env, target$binding, instrumented)
    state$replaced[[fn_plan$name]] <- list(
      name = fn_plan$name,
      binding = target$binding,
      env = target$env,
      original = target$fn,
      sites = nrow(fn_plan$sites)
    )
  }

  # Recorded rather than changed: R recompiles a closure whose body was
  # reassigned on its own, and the level explains a performance difference
  # between two otherwise identical campaigns.
  state$jit <- jit_level()

  invisible(instrumentation_report())
}

# A locked binding is the normal case in a namespace, so unlocking is part of
# the job rather than an error. The lock is restored even if assignment fails,
# so a half-instrumented package is never left writable.
replace_binding <- function(env, name, value) {
  locked <- environmentIsLocked(env) && bindingIsLocked(name, env)
  if (locked) {
    unlockBinding(name, env)
    on.exit(
      tryCatch(lockBinding(name, env), error = function(e) NULL),
      add = TRUE
    )
  }
  assign(name, value, envir = env)
  invisible(NULL)
}

jit_level <- function() {
  lvl <- suppressWarnings(as.integer(Sys.getenv("R_ENABLE_JIT", NA_character_)))
  if (!is.na(lvl)) {
    return(lvl)
  }
  # compiler::enableJIT() returns the *previous* level, so asking costs a
  # round trip rather than a read.
  previous <- compiler::enableJIT(-1L)
  previous
}

#' Restore every instrumented binding
#'
#' Mostly for tests and interactive work: a campaign process exits rather than
#' tidying up.
#'
#' @return Invisibly, the number of bindings restored.
#' @export
uninstrument <- function() {
  n <- 0L
  for (r in state$replaced) {
    ok <- tryCatch(
      {
        replace_binding(r$env, r$binding, r$original)
        TRUE
      },
      error = function(e) FALSE
    )
    if (ok) n <- n + 1L
  }
  reset_state()
  counter_thaw()
  counter_alloc(0)
  invisible(n)
}

#' What instrumentation did, and did not, reach
#'
#' Reports the selections that were instrumented, the regions the transformer
#' declined to enter, and any alias that still refers to an uninstrumented
#' copy. The last of these is the one worth reading: replacing a binding
#' cannot reach a closure someone already captured.
#'
#' @return A `zufuzz_instrumentation_report`.
#' @export
instrumentation_report <- function() {
  plan <- state$plan
  structure(
    list(
      version = instrumentation_version,
      digest = if (is.null(plan)) NA_character_ else plan_digest(plan),
      n_functions = length(state$replaced),
      n_sites = if (is.null(plan)) 0L else plan$n_sites,
      n_comparisons = if (is.null(plan)) 0L else plan$n_comparisons,
      functions = vapply(state$replaced, function(r) r$name, character(1)),
      skips = if (is.null(plan)) NULL else plan_skips(plan),
      aliases = find_aliases(state$replaced),
      jit = state$jit,
      sink = counter_sink(),
      frozen = counter_frozen()
    ),
    class = "zufuzz_instrumentation_report"
  )
}

# Replacing a binding updates one place. A copy taken before that -- a
# package that imported the function into its own namespace, or a closure that
# captured it -- still refers to the original and will not be counted.
# Reporting it is the honest alternative to pretending coverage is complete.
find_aliases <- function(replaced) {
  if (!length(replaced)) {
    return(character(0))
  }
  wanted <- unique(vapply(replaced, function(r) r$binding, character(1)))
  originals <- lapply(replaced, function(r) r$original)
  names(originals) <- vapply(replaced, function(r) r$binding, character(1))

  out <- character(0)
  for (ns_name in loadedNamespaces()) {
    if (ns_name %in% never_instrument) {
      next
    }
    ns <- tryCatch(asNamespace(ns_name), error = function(e) NULL)
    if (is.null(ns)) {
      next
    }
    imports <- parent.env(ns)
    if (!is.environment(imports)) {
      next
    }
    present <- intersect(ls(imports, all.names = TRUE), wanted)
    for (nm in present) {
      value <- tryCatch(get(nm, envir = imports, inherits = FALSE), error = function(e) NULL)
      if (!is.null(value) && identical(value, originals[[nm]])) {
        out <- c(out, paste0(ns_name, " imports an uninstrumented ", nm, "()"))
      }
    }
  }
  out
}

#' @export
print.zufuzz_instrumentation_report <- function(x, ...) {
  cat(sprintf(
    "<zufuzz instrumentation> %d function(s), %d site(s), %d comparison site(s)\n",
    x$n_functions, x$n_sites, x$n_comparisons
  ))
  if (!is.na(x$digest)) {
    cat(sprintf("  version %s, digest %s\n", x$version, substr(x$digest, 1, 12)))
  }
  cat(sprintf("  sink %s%s, JIT level %s\n",
    x$sink,
    if (isTRUE(x$frozen)) " (frozen)" else "",
    if (is.na(x$jit)) "unknown" else x$jit
  ))
  if (!is.null(x$skips) && nrow(x$skips)) {
    cat(sprintf("  %d region(s) not instrumented\n", nrow(x$skips)))
  }
  if (length(x$aliases)) {
    cat(sprintf("  %d uninstrumented alias(es):\n", length(x$aliases)))
    for (a in utils::head(x$aliases, 5L)) cat("    ", a, "\n", sep = "")
    if (length(x$aliases) > 5L) {
      cat("    ... and ", length(x$aliases) - 5L, " more\n", sep = "")
    }
  }
  if (x$n_sites == 0L) {
    cat("  nothing is instrumented: a campaign would be unguided\n")
  }
  invisible(x)
}
