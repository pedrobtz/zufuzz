# The harness entry point.
#
# `fuzz()` has three execution models (design section 4). Only run-once is
# implemented here: read each listed input, run the target on it, record what
# happened, and *return*. It never kills the process, it needs no engine, and
# it is what replay(), coverage reporting and the Windows story are built on.
#
# The worker loop (Stage 6) and the in-process companion engine reuse
# everything below the dispatch: the same target invocation, the same escaped
# error handling, the same sidecar.

# The environment variable lets a caller in another process -- replay(), and
# the launcher in Stage 5 -- decide where a harness writes its findings,
# without the harness script having to know or care.
default_artifact_dir <- function() {
  from_env <- Sys.getenv("ZUFUZZ_ARTIFACT_DIR", unset = "")
  if (nzchar(from_env)) {
    return(from_env)
  }
  file.path(".zufuzz", "artifacts")
}

#' Run a fuzzing harness
#'
#' The entry point a harness script calls. What it does depends on the engine:
#'
#' * `"none"` — run each listed input once and return. No engine needed, works
#'   everywhere, and never terminates the process. This is how [replay()] runs
#'   an artifact and how coverage over a corpus is reported.
#' * `"afl"`, `"libfuzzer"` — a campaign. These require an engine that is not
#'   part of this package; see the package documentation for how to install
#'   one. A campaign never returns, so `fuzz()` refuses to start one from an
#'   interactive session.
#'
#' @param test_one_input A function of one argument, called with a raw vector.
#'   Its return value is ignored; an escaped error is a finding.
#' @param args Character vector of inputs: file paths, or directories whose
#'   files are each run once. Defaults to the command line, so a harness run
#'   as `Rscript harness.R corpus/` does the obvious thing.
#' @param ... Engine flags. Accepted and validated by the engine.
#' @param engine Which execution model to use. `"auto"` picks the best
#'   available, which with no engine installed is `"none"`.
#' @param before_each A zero-argument function run before each input. Not
#'   counted as coverage.
#' @param rng_seed Integer. When given, R's RNG state is restored to this seed
#'   before every input, so a target that samples is still reproducible.
#' @param gc_torture `TRUE`, or an integer step for [gctorture2()]. Makes
#'   missing `PROTECT`s in native code fail loudly. Expect a large slowdown;
#'   restored on exit.
#' @param artifact_dir Where findings are written. Defaults to
#'   `.zufuzz/artifacts`.
#' @param coverage_out Path to write a coverage report for this run.
#' @param quiet Suppress the progress summary.
#' @return For `engine = "none"`, a `zufuzz_run` summarising the inputs,
#'   invisibly. Other engines do not return.
#' @export
#' @examples
#' target <- function(data) {
#'   if (length(data) > 2 && data[[1]] == as.raw(0x7a)) "z" else "other"
#' }
#' corpus <- tempfile()
#' dir.create(corpus)
#' writeBin(as.raw(c(0x7a, 0x75, 0x66)), file.path(corpus, "seed"))
#'
#' fuzz(target, args = corpus, engine = "none", artifact_dir = tempfile())
fuzz <- function(test_one_input,
                 args = commandArgs(trailingOnly = TRUE),
                 ...,
                 engine = c("auto", "none", "afl", "libfuzzer"),
                 before_each = NULL,
                 rng_seed = NULL,
                 gc_torture = FALSE,
                 artifact_dir = NULL,
                 coverage_out = NULL,
                 quiet = FALSE) {
  engine <- match.arg(engine)

  if (!is.function(test_one_input)) {
    stop("zufuzz: `test_one_input` must be a function", call. = FALSE)
  }
  if (length(formals(test_one_input)) < 1L) {
    stop("zufuzz: `test_one_input` must take one argument, the input bytes", call. = FALSE)
  }
  if (!is.null(before_each) && !is.function(before_each)) {
    stop("zufuzz: `before_each` must be a function or NULL", call. = FALSE)
  }
  if (isTRUE(state$in_fuzz)) {
    stop("zufuzz: fuzz() is already running in this process", call. = FALSE)
  }

  resolved <- resolve_engine(engine)

  if (!identical(resolved, "none")) {
    # A campaign either never returns or hands the process to a supervisor.
    # Either way it would take an interactive session with it.
    if (interactive()) {
      stop(
        "zufuzz: a campaign would end this session. Run the harness with ",
        "Rscript, or use engine = \"none\" to run inputs once.",
        call. = FALSE
      )
    }
    stop(
      "zufuzz: engine \"", resolved, "\" is not available in this build of ",
      "zufuzz yet; use engine = \"none\" to run listed inputs once.",
      call. = FALSE
    )
  }

  state$in_fuzz <- TRUE
  on.exit(state$in_fuzz <- FALSE, add = TRUE)

  run_once(
    test_one_input = test_one_input,
    inputs = collect_inputs(args),
    before_each = before_each,
    rng_seed = rng_seed,
    gc_torture = gc_torture,
    artifact_dir = artifact_dir %||% default_artifact_dir(),
    coverage_out = coverage_out,
    quiet = quiet
  )
}

`%||%` <- function(x, y) if (is.null(x)) y else x

# Design section 3's order. Only the last branch is implemented; the others
# are detected so that the error names what is present rather than pretending
# nothing is.
resolve_engine <- function(engine) {
  if (identical(engine, "auto")) {
    # An attached supervisor announces itself in the environment, which is how
    # the child half of AFL's protocol is meant to be discovered (Stage 6).
    if (nzchar(Sys.getenv("__AFL_SHM_ID"))) {
      return("afl")
    }
    # The companion package is checked for here from the stage that ships it.
    # Naming it earlier is not free: `R CMD check` warns about a
    # requireNamespace() call for a package that is not declared, and it
    # cannot be declared before it exists.
    return("none")
  }
  engine
}

# Positional arguments are files or directories, exactly as libFuzzer treats
# them. Anything beginning with "-" is an engine flag, not an input.
collect_inputs <- function(args) {
  args <- args[!startsWith(args, "-")]
  out <- character(0)
  for (a in args) {
    if (dir.exists(a)) {
      out <- c(out, sort(list.files(a, full.names = TRUE, recursive = FALSE)))
    } else if (file.exists(a)) {
      out <- c(out, a)
    } else {
      warning("zufuzz: no such input: ", a, call. = FALSE)
    }
  }
  out[!dir.exists(out)]
}

read_input <- function(path) {
  readBin(path, what = "raw", n = file.info(path)$size)
}

# gctorture is process-global, so it is always restored -- including when the
# target errors. This is the R-specific complement to a sanitizer: it makes a
# missing PROTECT in native code fail where it happens rather than later.
with_torture <- function(gc_torture, expr) {
  if (isFALSE(gc_torture) || is.null(gc_torture)) {
    return(expr)
  }
  if (isTRUE(gc_torture)) {
    previous <- gctorture(TRUE)
    on.exit(gctorture(previous), add = TRUE)
  } else {
    step <- as.integer(gc_torture)
    gctorture2(step)
    on.exit(gctorture2(0L), add = TRUE)
  }
  expr
}

#' Run the target on one input and classify what happened
#'
#' Shared by every execution model, so that a finding means the same thing
#' whichever one produced it.
#'
#' @return A list with `kind` (`"normal"` or `"error"`), and for an error the
#'   fingerprint, condition and bounded traceback.
#' @noRd
invoke_target <- function(test_one_input, bytes, before_each = NULL,
                          rng_state = NULL) {
  # Everything already on the stack belongs to the caller, not to the target.
  base_depth <- length(sys.calls())

  if (!is.null(rng_state)) {
    assign(".Random.seed", rng_state, envir = globalenv())
  }
  if (!is.null(before_each)) {
    before_each()
  }

  frames <- NULL
  cnd <- tryCatch(
    {
      withCallingHandlers(
        {
          test_one_input(bytes)
          NULL
        },
        error = function(e) {
          # Captured here, while the stack still exists; by the time tryCatch
          # runs the frames are gone.
          frames <<- sys.calls()
        }
      )
    },
    error = function(e) e
  )

  if (is.null(cnd)) {
    return(list(kind = "normal"))
  }

  fp <- fingerprint_condition(cnd)
  expected <- expected_fingerprint()
  if (!is.null(expected) && !identical(fp$digest, expected)) {
    # A different bug. Reported as normal so that a minimizer cannot shrink
    # one finding into another and call it progress.
    return(list(kind = "normal", suppressed = fp$digest))
  }

  list(
    kind = "error",
    fingerprint = fp,
    condition = cnd,
    traceback = bounded_traceback(frames, base_depth = base_depth)
  )
}

# The diagnostic the user actually reads. Written to stderr because that is
# where a harness's diagnostics belong, and from R rather than from C -- the
# shared object is not allowed to write to the standard streams.
report_finding <- function(outcome, path) {
  msg <- c(
    "==zufuzz== Uncaught R error",
    paste0("  classes:     ", paste(outcome$fingerprint$classes, collapse = ", ")),
    paste0("  message:     ", outcome$fingerprint$message),
    paste0("  call:        ", outcome$fingerprint$call),
    paste0("  fingerprint: ", outcome$fingerprint$digest),
    if (!is.na(path)) paste0("  artifact:    ", path)
  )
  if (length(outcome$traceback)) {
    msg <- c(msg, "  traceback:", paste0("    ", outcome$traceback))
  }
  message(paste(msg, collapse = "\n"))
}

run_once <- function(test_one_input, inputs, before_each, rng_seed,
                     gc_torture, artifact_dir, coverage_out, quiet) {
  rng_state <- NULL
  if (!is.null(rng_seed)) {
    # Captured once and copied back per input: cheaper than re-seeding, and it
    # makes a sample()-dependent target reproducible without the target
    # knowing anything about it.
    old <- if (exists(".Random.seed", envir = globalenv())) {
      get(".Random.seed", envir = globalenv())
    } else {
      NULL
    }
    set.seed(rng_seed)
    rng_state <- get(".Random.seed", envir = globalenv())
    on.exit(
      if (!is.null(old)) assign(".Random.seed", old, envir = globalenv()),
      add = TRUE
    )
  }

  findings <- list()
  counter_reset()

  for (path in inputs) {
    bytes <- read_input(path)
    outcome <- with_torture(
      gc_torture,
      invoke_target(test_one_input, bytes, before_each, rng_state)
    )
    if (identical(outcome$kind, "error")) {
      sidecar <- new_sidecar(
        bytes,
        kind = "crash",
        fingerprint = outcome$fingerprint,
        traceback = outcome$traceback,
        harness = harness_path(),
        rng_seed = rng_seed,
        engine = "none"
      )
      written <- write_artifact(bytes, sidecar, artifact_dir)
      report_finding(outcome, written)
      findings[[length(findings) + 1L]] <- list(
        input = path,
        artifact = written,
        fingerprint = outcome$fingerprint$digest
      )
    }
  }

  if (!is.null(coverage_out)) {
    write_coverage(coverage_out)
  }

  result <- structure(
    list(
      engine = "none",
      inputs = length(inputs),
      findings = findings,
      coverage = coverage_summary()
    ),
    class = "zufuzz_run"
  )

  if (!quiet) {
    print(result)
  }
  invisible(result)
}

# The script R is running, when there is one. Recorded in a sidecar so a
# finding can say what produced it.
harness_path <- function() {
  args <- commandArgs(trailingOnly = FALSE)
  hit <- grep("^--file=", args, value = TRUE)
  if (!length(hit)) {
    return(NA_character_)
  }
  normalizePath(sub("^--file=", "", hit[[1L]]), mustWork = FALSE)
}

write_coverage <- function(path) {
  sites <- coverage_sites()
  dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
  jsonlite::write_json(
    list(
      schema = sidecar_schema_version,
      instrumentation = instrumentation_report()$digest,
      summary = coverage_summary(sites),
      sites = sites
    ),
    path,
    auto_unbox = TRUE,
    null = "null",
    pretty = TRUE
  )
  invisible(path)
}

#' @export
print.zufuzz_run <- function(x, ...) {
  cat(sprintf("<zufuzz run> engine %s, %d input(s)\n", x$engine, x$inputs))
  if (length(x$findings)) {
    cat(sprintf("  %d finding(s):\n", length(x$findings)))
    for (f in x$findings) {
      cat(sprintf("    %s  %s\n", substr(f$fingerprint, 1, 12), f$artifact))
    }
  } else {
    cat("  no findings\n")
  }
  if (!is.na(x$coverage$proportion)) {
    cat(sprintf(
      "  coverage %d/%d sites (%.0f%%)\n",
      x$coverage$reached, x$coverage$sites, 100 * x$coverage$proportion
    ))
  }
  invisible(x)
}
