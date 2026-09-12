# Re-running an artifact in a process that has never seen the engine.
#
# Design section 9 keeps three claims apart, and replay() answers the middle
# one:
#
#   input reproduction   the artifact holds the bytes that were given
#   finding reproduction a fresh, uninstrumented process fails the same way
#   campaign determinism same flags and seed produce the same decisions
#
# "Uninstrumented" is the part that matters. A finding that only reproduces
# against rewritten code is a finding about zufuzz, not about the target, and
# reporting it as the latter would waste someone's afternoon.

rscript_path <- function() {
  file.path(R.home("bin"), if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript")
}

#' Re-run one artifact through its harness, in a fresh process
#'
#' Runs `Rscript <harness> <input>`, which reaches [fuzz()]'s run-once mode:
#' no engine, no campaign, and a process that returns rather than dying.
#'
#' @param harness Path to the harness script that produced the artifact.
#' @param input Path to the artifact.
#' @param instrument Run with instrumentation on. The default is off, which is
#'   the claim worth making; `TRUE` is for telling instrumentation-dependent
#'   behaviour apart from history-dependent behaviour.
#' @param expect Fingerprint this replay should confirm. Usually taken from
#'   the artifact's sidecar; give it explicitly to check against something
#'   else.
#' @param timeout Seconds before the child is killed.
#' @return A `zufuzz_replay`.
#' @export
replay <- function(harness, input, instrument = FALSE, expect = NULL,
                   timeout = 60) {
  if (!file.exists(harness)) {
    stop("zufuzz: no such harness: ", harness, call. = FALSE)
  }
  if (!file.exists(input)) {
    stop("zufuzz: no such artifact: ", input, call. = FALSE)
  }

  recorded <- read_sidecar(input)
  if (is.null(expect) && !is.null(recorded)) {
    expect <- recorded$fingerprint
  }

  out_dir <- tempfile("zufuzz-replay-")
  dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)
  on.exit(unlink(out_dir, recursive = TRUE), add = TRUE)

  child_env <- c(
    Sys.getenv(),
    ZUFUZZ_ARTIFACT_DIR = out_dir,
    # R installs handlers for SIGSEGV/SIGILL/SIGBUS that turn a native crash
    # into a tidy message and a clean exit. For replay that would hide the
    # very thing being reproduced.
    R_NO_SEGV_HANDLER = "1"
  )
  if (!instrument) {
    child_env[["ZUFUZZ_NO_INSTRUMENT"]] <- "1"
  } else {
    child_env <- child_env[names(child_env) != "ZUFUZZ_NO_INSTRUMENT"]
  }

  run <- processx::run(
    rscript_path(),
    c("--vanilla", harness, input),
    env = child_env,
    error_on_status = FALSE,
    timeout = timeout,
    stderr_to_stdout = FALSE
  )

  outcome <- classify_replay(run, out_dir)
  outcome$confirmed <- !is.null(expect) &&
    identical(outcome$fingerprint, expect)
  outcome$expected <- expect
  outcome$environment_mismatches <- environment_mismatches(recorded$environment)
  outcome$harness <- harness
  outcome$input <- input
  structure(outcome, class = "zufuzz_replay")
}

# The sidecar the child wrote is the evidence, not the text it printed. A
# harness is free to print whatever it likes; the sidecar has a schema.
classify_replay <- function(run, out_dir) {
  sidecars <- list.files(out_dir, pattern = "\\.json$", full.names = TRUE)

  if (length(sidecars)) {
    written <- jsonlite::read_json(sidecars[[1L]], simplifyVector = TRUE)
    return(list(
      outcome = "error",
      fingerprint = written$fingerprint,
      condition = written$condition,
      traceback = written$traceback,
      status = run$status,
      stderr = run$stderr
    ))
  }

  if (isTRUE(run$timeout)) {
    return(list(
      outcome = "timeout", fingerprint = NULL,
      status = run$status, stderr = run$stderr
    ))
  }
  # A non-zero status with no sidecar means the process died before it could
  # write one: a native crash, or the harness itself failing to load. No R
  # code ran afterwards, so there is no condition to fingerprint and whatever
  # can be recovered has to come out of the log.
  if (!identical(run$status, 0L)) {
    native <- native_finding(run$stderr, run$status)
    if (is.null(native)) {
      # Exited non-zero, no report, no signal: the harness failed to load or
      # refused its input. Calling that a crash would invent a finding.
      return(list(
        outcome = "infrastructure", fingerprint = NULL,
        status = run$status, stderr = run$stderr
      ))
    }
    fp <- fingerprint_sanitizer(native)
    return(list(
      # A described defect and a bare death are different claims, and only the
      # first can be confirmed against a recorded fingerprint.
      outcome = if (identical(native$kind, "signal")) "signal" else "sanitizer",
      fingerprint = if (is.null(fp)) NULL else fp$digest,
      native = native,
      status = run$status,
      stderr = run$stderr
    ))
  }
  list(outcome = "normal", fingerprint = NULL, status = 0L, stderr = run$stderr)
}

#' @export
print.zufuzz_replay <- function(x, ...) {
  cat(sprintf("<zufuzz replay> %s\n", x$outcome))
  if (!is.null(x$fingerprint)) {
    cat(sprintf("  fingerprint %s\n", substr(x$fingerprint, 1, 12)))
  }
  if (!is.null(x$expected)) {
    cat(sprintf(
      "  %s the recorded finding\n",
      if (isTRUE(x$confirmed)) "confirms" else "does NOT confirm"
    ))
  }
  if (length(x$environment_mismatches)) {
    cat("  environment differs from the recording:\n")
    for (m in utils::head(x$environment_mismatches, 5L)) cat("    ", m, "\n", sep = "")
  }
  invisible(x)
}
