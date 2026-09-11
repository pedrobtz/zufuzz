# Running a harness in a child process, and deciding what happened.
#
# The classification rule is design section 12's, and it is the opposite of
# the obvious one: **the artifact directory is the evidence, and the exit code
# only corroborates.** Engines disagree about exit codes -- libFuzzer encodes
# the outcome, `afl-fuzz` exits 0 whether or not it found crashes, and
# run-once returns normally by design -- but every one of them writes an
# artifact when it finds something.

#' Run a fuzzing harness in a child process
#'
#' The way to start a campaign from a live session or from CI: the harness
#' runs in its own process, so a finding that kills that process is a result
#' rather than the end of yours.
#'
#' @param path Path to the harness script.
#' @param corpus Corpus directory, or `NULL`.
#' @param args Extra arguments passed through to the harness.
#' @param ... Engine flags, as named arguments.
#' @param engine Which engine to run under; `"auto"` picks the best available.
#' @param time_limit Seconds before the campaign is stopped.
#' @param runs Maximum inputs to try.
#' @param artifact_dir Where findings are collected. A temporary directory by
#'   default, so a run cannot quietly litter the working directory.
#' @param env Named character vector of extra environment variables.
#' @param coverage Report coverage over the corpus after the run.
#' @param quiet Suppress the summary.
#' @return A `zufuzz_result`.
#' @export
fuzz_file <- function(path, corpus = NULL, args = character(), ...,
                      engine = c("auto", "none", "afl", "libfuzzer"),
                      time_limit = Inf, runs = Inf,
                      artifact_dir = NULL, env = character(),
                      coverage = FALSE, quiet = FALSE) {
  engine <- match.arg(engine)
  if (!file.exists(path)) {
    stop("zufuzz: no such harness: ", path, call. = FALSE)
  }

  resolved <- resolve_engine(engine)
  if (!identical(resolved, "none") && !engine_available(resolved)) {
    return(infrastructure_result(
      resolved,
      sprintf(
        "engine \"%s\" is not available; see engines() for what is installed",
        resolved
      )
    ))
  }
  if (!identical(resolved, "none")) {
    return(infrastructure_result(
      resolved,
      sprintf("engine \"%s\" is not implemented in this release", resolved)
    ))
  }

  artifact_dir <- artifact_dir %||% tempfile("zufuzz-artifacts-")
  dir.create(artifact_dir, recursive = TRUE, showWarnings = FALSE)
  before <- artifact_inventory(artifact_dir)

  child_env <- c(
    Sys.getenv(),
    ZUFUZZ_ARTIFACT_DIR = artifact_dir,
    # R's own SIGSEGV/SIGILL/SIGBUS handlers turn a native crash into a tidy
    # message and a clean exit, which would hide exactly what a campaign is
    # looking for.
    R_NO_SEGV_HANDLER = "1"
  )
  for (nm in names(env)) {
    child_env[[nm]] <- env[[nm]]
  }

  argv <- c("--vanilla", path, corpus, args, flag_arguments(list(...)))
  argv <- argv[!is.na(argv) & nzchar(argv)]

  started <- Sys.time()
  run <- tryCatch(
    processx::run(
      rscript_path(), argv,
      env = child_env,
      error_on_status = FALSE,
      # processx wants a time interval, and treats Inf as "no limit"; NULL is
      # rejected outright.
      timeout = if (is.finite(time_limit)) time_limit else Inf,
      stderr_to_stdout = FALSE
    ),
    # Ctrl-C in the caller must not leave an orphan; processx kills the child
    # when the run is interrupted, and this turns it into a result rather than
    # an error escaping into the caller's session.
    interrupt = function(cnd) structure(list(interrupted = TRUE), class = "zufuzz_interrupted")
  )
  elapsed <- as.numeric(difftime(Sys.time(), started, units = "secs"))

  if (inherits(run, "zufuzz_interrupted")) {
    return(new_result(
      engine = resolved, stop_reason = "interrupted", findings = list(),
      elapsed = elapsed, artifact_dir = artifact_dir, quiet = quiet
    ))
  }

  findings <- collect_findings(artifact_dir, before)
  reason <- classify_run(run, findings)

  result <- new_result(
    engine = resolved,
    stop_reason = reason,
    findings = findings,
    elapsed = elapsed,
    artifact_dir = artifact_dir,
    status = run$status,
    stdout = run$stdout,
    stderr = run$stderr,
    timed_out = isTRUE(run$timeout),
    quiet = quiet
  )
  result
}

# Named arguments become engine flags. Shared by every engine because the
# spelling is the engine's business, not the launcher's.
flag_arguments <- function(dots) {
  if (!length(dots)) {
    return(character(0))
  }
  nms <- names(dots)
  if (is.null(nms) || any(!nzchar(nms))) {
    stop("zufuzz: engine flags must be named, e.g. max_len = 4096", call. = FALSE)
  }
  paste0("-", nms, "=", vapply(dots, as.character, character(1)))
}

artifact_inventory <- function(dir) {
  list.files(dir, pattern = "^(crash|timeout|oom)-[0-9a-f]+$")
}

collect_findings <- function(dir, before) {
  now <- artifact_inventory(dir)
  fresh <- setdiff(now, before)
  lapply(sort(fresh), function(name) {
    path <- file.path(dir, name)
    sidecar <- read_sidecar(path)
    list(
      artifact = path,
      kind = sub("-.*$", "", name),
      fingerprint = sidecar$fingerprint %||% NA_character_,
      sidecar = sidecar
    )
  })
}

# Artifacts first, exit status second. A harness that fails to load produces
# no artifact and a non-zero status; a campaign that exhausts its budget
# produces no artifact and a zero status; either can look like the other if
# you read only one of them.
classify_run <- function(run, findings) {
  if (length(findings)) {
    return("finding")
  }
  # `time_limit` is the caller's budget, not a per-input timeout. Reaching it
  # means the campaign ran out of wall clock with nothing found, which is
  # `budget`. A timeout *finding* is a `timeout-<sha1>` artifact written by
  # the engine because one input hung, and that is handled above.
  if (isTRUE(run$timeout)) {
    return("budget")
  }
  if (identical(run$status, 0L)) {
    return("budget")
  }
  "infrastructure"
}

infrastructure_result <- function(engine, message) {
  new_result(
    engine = engine, stop_reason = "infrastructure", findings = list(),
    elapsed = 0, artifact_dir = NA_character_, stderr = message, quiet = TRUE
  )
}

new_result <- function(engine, stop_reason, findings, elapsed, artifact_dir,
                       status = NA_integer_, stdout = "", stderr = "",
                       timed_out = FALSE, quiet = TRUE) {
  result <- structure(
    list(
      engine = engine,
      stop_reason = stop_reason,
      findings = findings,
      finding = if (length(findings)) findings[[1L]] else NULL,
      elapsed = elapsed,
      status = status,
      timed_out = timed_out,
      artifact_dir = artifact_dir,
      stdout = stdout,
      stderr = stderr
    ),
    class = "zufuzz_result"
  )
  if (!quiet) {
    print(result)
  }
  result
}

#' @export
print.zufuzz_result <- function(x, ...) {
  cat(sprintf(
    "<zufuzz result> %s via %s, %.1fs\n",
    x$stop_reason, x$engine, x$elapsed
  ))
  if (length(x$findings)) {
    cat(sprintf("  %d finding(s):\n", length(x$findings)))
    for (f in x$findings) {
      cat(sprintf(
        "    %-8s %s %s\n", f$kind,
        if (is.na(f$fingerprint)) "            " else substr(f$fingerprint, 1, 12),
        basename(f$artifact)
      ))
    }
  }
  if (identical(x$stop_reason, "infrastructure") && nzchar(x$stderr)) {
    cat("  ", utils::tail(strsplit(x$stderr, "\n")[[1L]], 3L), sep = "\n  ")
    cat("\n")
  }
  invisible(x)
}
