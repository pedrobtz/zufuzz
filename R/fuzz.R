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
    if (!identical(resolved, "afl")) {
      stop(
        "zufuzz: engine \"", resolved, "\" is not available in this build of ",
        "zufuzz yet; use engine = \"none\" to run listed inputs once.",
        call. = FALSE
      )
    }
    # A supervisor announces itself before exec'ing the target. Without one,
    # the fork server handshake would fail on its first write and the harness
    # would return having done nothing at all -- so say what is wrong instead.
    if (!nzchar(Sys.getenv("__AFL_SHM_ID"))) {
      stop(
        "zufuzz: engine \"afl\" needs a supervisor. Run this harness under ",
        "afl-fuzz, or through fuzz_file(engine = \"afl\"); ",
        "engine = \"none\" runs listed inputs once.",
        call. = FALSE
      )
    }
  }

  state$in_fuzz <- TRUE
  on.exit(state$in_fuzz <- FALSE, add = TRUE)

  if (identical(resolved, "afl")) {
    return(invisible(run_afl_worker(
      test_one_input = test_one_input,
      before_each = before_each,
      rng_seed = rng_seed,
      gc_torture = gc_torture,
      artifact_dir = artifact_dir %||% default_artifact_dir()
    )))
  }

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

# -- the AFL worker ------------------------------------------------------

# `tools` exports SIGKILL, SIGTERM and friends, but not SIGABRT, so the number
# is written out. POSIX fixes it at 6 on every platform an AFL supervisor runs
# on, and it is the right signal for this:
#
#   SIGKILL  is what AFL itself sends a child that overran its timeout, so a
#            child that killed itself that way would be filed as a hang.
#   SIGUSR1  is what python-afl uses, but R installs a handler for it that
#            saves a workspace and quits -- a clean exit, which AFL would read
#            as "this input was fine".
#   SIGABRT  R installs no handler, and AFL counts any signal death as a
#            crash.
signal_abort <- 6L

# Under a supervisor the input arrives one of two ways: written to a fixed
# file whose path AFL substituted for `@@`, or on stdin. The file is
# preferred because AFL rewrites the same path each round, so reading it is
# cheaper and unambiguous.
afl_read_input <- function(max_bytes = 1e7) {
  args <- commandArgs(trailingOnly = TRUE)
  candidates <- args[!startsWith(args, "-")]
  candidates <- candidates[file.exists(candidates) & !dir.exists(candidates)]
  if (length(candidates)) {
    return(read_input(candidates[[length(candidates)]]))
  }
  con <- file("stdin", "rb")
  on.exit(close(con), add = TRUE)
  readBin(con, what = "raw", n = max_bytes)
}

#' Run as an AFL worker
#'
#' Attaches to the supervisor's bitmap, then becomes a deferred fork server.
#' The parent never returns from the handshake: it *is* the fork server. Each
#' child comes back with one input to run, runs it, and quits -- so everything
#' after the `.Call()` below executes only in a child.
#'
#' @noRd
run_afl_worker <- function(test_one_input, before_each, rng_seed, gc_torture,
                           artifact_dir) {
  attached <- afl_attach_map()

  rng_state <- NULL
  if (!is.null(rng_seed)) {
    set.seed(rng_seed)
    rng_state <- get(".Random.seed", envir = globalenv())
  }

  repeat {
    in_child <- .Call(C_zufuzz_afl_forkserver)
    if (!isTRUE(in_child)) {
      # No supervisor was listening, or it went away. Returning lets R exit
      # through its own path rather than waiting to be killed.
      break
    }

    bytes <- afl_read_input()
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
        engine = "afl"
      )
      written <- tryCatch(
        write_artifact(bytes, sidecar, artifact_dir),
        error = function(e) NA_character_
      )
      report_finding(outcome, written)
      flush(stderr())

      # The supervisor decides what a crash is by how the child died, so the
      # child has to actually die of a signal. Raised from R rather than from
      # compiled code: zufuzz.so is not allowed to abort, and does not need
      # to be.
      tools::pskill(Sys.getpid(), signal_abort)
    }

    # A child runs exactly one input. Not persistent mode: that would save a
    # fork per input but doubles the protocol state machine, and for an R
    # target the fork is not the expensive part. Stage 12 benchmarks decide.
    quit(save = "no", status = 0L, runLast = FALSE)
  }

  invisible(attached)
}

afl_attach_map <- function() {
  shm_id <- Sys.getenv("__AFL_SHM_ID", unset = "")
  if (!nzchar(shm_id)) {
    return(FALSE)
  }
  size <- suppressWarnings(as.numeric(Sys.getenv("AFL_MAP_SIZE", unset = "")))
  if (!isTRUE(is.finite(size)) || size <= 0) {
    size <- 65536
  }
  if (!isTRUE(.Call(C_zufuzz_afl_attach, shm_id, size))) {
    # Worth a word: the campaign will run, but with no feedback at all, and
    # silence here would look like a target with no branches.
    message(
      "==zufuzz== could not attach to the AFL coverage map; ",
      "the campaign will run unguided"
    )
    return(FALSE)
  }
  counter_attach(
    "afl",
    .Call(C_zufuzz_afl_map_ptr),
    size = .Call(C_zufuzz_afl_map_size)
  )
  TRUE
}
