# Which closures a campaign would instrument.
#
# Selection is separate from planning so that the awkward part -- what a name
# refers to, what cannot be instrumented, and what must never be -- is
# answerable and testable without walking a single AST.
#
# All internal until Stage 3.

# Fixed by R itself, so a literal list is honest and cheap; resolving them
# through installed.packages() at selection time would be neither.
base_package_names <- c(
  "base", "compiler", "datasets", "grDevices", "graphics", "grid",
  "methods", "parallel", "splines", "stats", "stats4", "tcltk", "tools",
  "utils"
)

recommended_package_names <- c(
  "boot", "class", "cluster", "codetools", "foreign", "KernSmooth",
  "lattice", "MASS", "Matrix", "mgcv", "nlme", "nnet", "rpart", "spatial",
  "survival"
)

# zufuzz is never instrumented, under any option, in any entry point.
#
# Not a style rule: the provider, the object generator and the worker loop all
# run once per input, inside the campaign. Instrumenting them would feed the
# engine's own execution back as target coverage, so every input would look
# like it discovered something and the feedback signal would be noise.
never_instrument <- "zufuzz"

new_selection <- function(name, fn = NULL, source = NA_character_,
                          status = "ok", reason = NA_character_) {
  list(
    name = name, fn = fn, source = source,
    status = status, reason = reason
  )
}

skipped <- function(name, reason, source = NA_character_) {
  new_selection(name, NULL, source, "skipped", reason)
}

# Why a binding cannot be instrumented, or NA if it can.
unsupported_reason <- function(value) {
  if (is.null(value)) {
    return("binding is NULL")
  }
  if (!is.function(value)) {
    return(paste0("not a function (", class(value)[[1L]], ")"))
  }
  if (is.primitive(value)) {
    return("primitive: no R body to instrument")
  }
  # Checked with inherits() rather than methods::is() so that selection needs
  # no dependency on methods; these are the class names a generic or a
  # generator actually carries.
  if (inherits(value, c("standardGeneric", "genericFunction", "nonstandardGenericFunction"))) {
    return("S4 generic: out of scope for 0.1")
  }
  if (inherits(value, c("MethodDefinition", "refObjectGenerator", "R6ClassGenerator"))) {
    return("S4/RC/R6 method or generator: out of scope for 0.1")
  }
  if (is.null(body(value))) {
    return("no body")
  }
  NA_character_
}

#' Resolve one selection string
#'
#' Accepts `"pkg::fn"`, `"pkg:::fn"`, or a bare name looked up in `envir`.
#'
#' @noRd
resolve_selection <- function(spec, envir = parent.frame()) {
  if (!is.character(spec) || length(spec) != 1L || is.na(spec)) {
    stop("zufuzz: a selection must be a single string", call. = FALSE)
  }

  parts <- regmatches(spec, regexec("^([^:]+):::?([^:]+)$", spec))[[1L]]

  if (length(parts) == 3L) {
    pkg <- parts[[2L]]
    nm <- parts[[3L]]
    if (pkg %in% never_instrument) {
      return(skipped(spec, "zufuzz is never instrumented", "namespace"))
    }
    ns <- tryCatch(asNamespace(pkg), error = function(e) NULL)
    if (is.null(ns)) {
      return(skipped(spec, paste0("namespace '", pkg, "' is not loaded"), "namespace"))
    }
    if (!exists(nm, envir = ns, inherits = FALSE)) {
      return(skipped(spec, paste0("no binding '", nm, "' in '", pkg, "'"), "namespace"))
    }
    value <- get(nm, envir = ns, inherits = FALSE)
    reason <- unsupported_reason(value)
    if (!is.na(reason)) {
      return(skipped(spec, reason, "namespace"))
    }
    return(new_selection(spec, value, "namespace"))
  }

  if (grepl(":", spec, fixed = TRUE)) {
    return(skipped(spec, "malformed selection", NA_character_))
  }

  if (!exists(spec, envir = envir)) {
    return(skipped(spec, "no such binding in the calling environment", "local"))
  }
  value <- get(spec, envir = envir)
  reason <- unsupported_reason(value)
  if (!is.na(reason)) {
    return(skipped(spec, reason, "local"))
  }
  new_selection(spec, value, "local")
}

#' Every instrumentable closure in a namespace, plus its S3 methods
#'
#' S3 methods are taken from `.__S3MethodsTable__.` as well as the namespace,
#' because a method registered for a generic in another package is reachable
#' only through that table -- instrumenting the namespace alone would leave
#' dispatch uninstrumented and the coverage quietly incomplete.
#'
#' @noRd
select_package <- function(pkg, exclude = character()) {
  if (pkg %in% never_instrument) {
    return(list(skipped(pkg, "zufuzz is never instrumented", "package")))
  }
  ns <- tryCatch(asNamespace(pkg), error = function(e) NULL)
  if (is.null(ns)) {
    return(list(skipped(pkg, paste0("namespace '", pkg, "' is not loaded"), "package")))
  }

  out <- list()

  for (nm in sort(ls(ns, all.names = TRUE))) {
    qualified <- paste0(pkg, ":::", nm)
    if (nm %in% exclude || qualified %in% exclude) {
      next
    }
    value <- tryCatch(get(nm, envir = ns, inherits = FALSE), error = function(e) NULL)
    reason <- unsupported_reason(value)
    if (!is.na(reason)) {
      # Only report skips that a user might have expected to work; a
      # namespace is full of data objects and reporting each is noise.
      if (is.function(value)) {
        out[[length(out) + 1L]] <- skipped(qualified, reason, "namespace")
      }
      next
    }
    out[[length(out) + 1L]] <- new_selection(qualified, value, "namespace")
  }

  s3 <- tryCatch(
    get(".__S3MethodsTable__.", envir = ns, inherits = FALSE),
    error = function(e) NULL
  )
  if (is.environment(s3)) {
    for (nm in sort(ls(s3, all.names = TRUE))) {
      qualified <- paste0(pkg, ":::S3:", nm)
      if (nm %in% exclude || qualified %in% exclude) {
        next
      }
      value <- tryCatch(get(nm, envir = s3, inherits = FALSE), error = function(e) NULL)
      if (!is.na(unsupported_reason(value))) {
        next
      }
      out[[length(out) + 1L]] <- new_selection(qualified, value, "s3")
    }
  }

  out
}

#' Dependency closure of a package over Imports and Depends
#'
#' Breadth-first with a seen set, so a cyclic or diamond dependency graph
#' resolves once each rather than looping.
#'
#' @noRd
package_dependencies <- function(pkg, seen = character()) {
  queue <- pkg
  while (length(queue)) {
    current <- queue[[1L]]
    queue <- queue[-1L]
    if (current %in% seen || current %in% never_instrument) {
      next
    }
    seen <- c(seen, current)

    deps <- tryCatch(
      {
        desc <- utils::packageDescription(current)
        fields <- unlist(desc[c("Imports", "Depends")], use.names = FALSE)
        fields <- fields[!is.na(fields)]
        if (!length(fields)) {
          character()
        } else {
          parsed <- unlist(strsplit(paste(fields, collapse = ","), ","))
          parsed <- trimws(sub("\\(.*", "", parsed))
          parsed[nzchar(parsed) & parsed != "R"]
        }
      },
      error = function(e) character()
    )
    queue <- c(queue, setdiff(deps, seen))
  }
  seen
}

#' @noRd
select_packages <- function(pkgs, exclude = character(), recursive = FALSE) {
  pkgs <- setdiff(unique(pkgs), never_instrument)
  if (recursive) {
    pkgs <- unique(unlist(lapply(pkgs, package_dependencies)))
    pkgs <- setdiff(pkgs, never_instrument)
  }
  pkgs <- sort(setdiff(pkgs, exclude))
  # Only what is actually loaded: selection happens after library(), and a
  # namespace that was never loaded has no bindings to replace.
  pkgs <- pkgs[pkgs %in% loadedNamespaces()]
  unlist(lapply(pkgs, select_package, exclude = exclude), recursive = FALSE)
}

#' @noRd
select_all <- function(exclude = character(), include_base = FALSE) {
  pkgs <- loadedNamespaces()
  if (!include_base) {
    pkgs <- setdiff(pkgs, c(base_package_names, recommended_package_names))
  }
  # never_instrument is applied by select_packages() too; stated twice on
  # purpose, because this is the entry point most likely to be widened later.
  pkgs <- setdiff(pkgs, never_instrument)
  select_packages(pkgs, exclude = exclude, recursive = FALSE)
}

#' Turn selections into a campaign plan
#'
#' @noRd
plan_selections <- function(selections) {
  ok <- Filter(function(s) identical(s$status, "ok"), selections)
  plans <- list()
  for (s in ok) {
    if (!is.null(plans[[s$name]])) {
      next # a duplicate selection is not a second set of counters
    }
    plans[[s$name]] <- plan_function(s$fn, s$name)
  }
  new_plan(plans)
}
