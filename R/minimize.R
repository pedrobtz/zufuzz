# Shrinking a finding without changing which finding it is.
#
# The property that makes this worth writing rather than delegating: neither
# libFuzzer's `-minimize_crash` nor `afl-tmin` knows what bug it is shrinking.
# Both treat *any* death as "still crashes", so both will happily walk from
# the bug you are minimizing into a different, smaller one and report success.
# Every candidate here is confirmed against the original fingerprint.
#
# That is also why the reducer is engine-neutral R rather than a wrapper: it
# has to work with no engine installed, and on Windows, where the accelerators
# do not exist at all.

#' Shrink a finding to a smaller input that fails the same way
#'
#' Each candidate is re-run through [replay()] in a fresh process and kept
#' only if it reproduces the *same* fingerprint. A candidate that fails
#' differently is rejected, however much smaller it is.
#'
#' @param harness Path to the harness that produced the finding.
#' @param finding Path to the artifact.
#' @param out Where to write the minimized artifact. Defaults to a file beside
#'   `finding` with a `.min` suffix.
#' @param runs Maximum number of candidates to try. Each one is a fresh
#'   process, so this is the real cost control.
#' @param accelerate Use `afl-tmin` first when it is available, then finish
#'   with the gated reducer. The accelerator is never trusted on its own.
#' @param timeout Seconds allowed for each candidate.
#' @return A `zufuzz_minimize`.
#' @export
minimize <- function(harness, finding, out = NULL, runs = 1000,
                     accelerate = TRUE, timeout = 60) {
  if (!file.exists(harness)) {
    stop("zufuzz: no such harness: ", harness, call. = FALSE)
  }
  if (!file.exists(finding)) {
    stop("zufuzz: no such artifact: ", finding, call. = FALSE)
  }
  if (!is.numeric(runs) || length(runs) != 1L || is.na(runs) || runs < 3) {
    # Fewer than three leaves no budget to confirm the original, try anything,
    # and reconfirm the result -- so the answer would be untrustworthy rather
    # than merely unminimized.
    stop("zufuzz: `runs` must be at least 3", call. = FALSE)
  }

  recorded <- read_sidecar(finding)
  refusal <- refuse_to_minimize(recorded)
  if (!is.null(refusal)) {
    return(new_minimize_result(finding, NA_character_, refusal, list()))
  }
  target_fp <- recorded$fingerprint

  budget <- new.env(parent = emptyenv())
  budget$left <- as.integer(runs)

  # Confirm before shrinking. Minimizing something that no longer reproduces
  # would produce a confident answer about nothing.
  if (!still_fails(harness, read_input(finding), target_fp, timeout, budget)) {
    return(new_minimize_result(
      finding, NA_character_,
      "the finding does not reproduce, so there is nothing to minimize",
      list()
    ))
  }

  original <- read_input(finding)
  bytes <- original

  if (isTRUE(accelerate)) {
    bytes <- accelerated_candidate(harness, finding, target_fp, timeout, budget, bytes)
  }

  bytes <- reduce_bytes(harness, bytes, target_fp, timeout, budget)

  # Reconfirm what is actually being handed back, not what the last accepted
  # candidate was believed to be.
  confirmed <- still_fails(harness, bytes, target_fp, timeout, budget)

  out <- out %||% paste0(finding, ".min")
  if (confirmed) {
    sidecar <- recorded
    sidecar$artifact <- basename(out)
    sidecar$sha1 <- bytes_digest(bytes)
    sidecar$length <- length(bytes)
    writeBin(bytes, out)
    jsonlite::write_json(sidecar, paste0(out, ".json"),
      auto_unbox = TRUE, null = "null", pretty = TRUE
    )
  }

  new_minimize_result(
    finding,
    if (confirmed) out else NA_character_,
    if (confirmed) NA_character_ else "the minimized candidate did not reconfirm",
    list(
      original_bytes = length(original),
      minimized_bytes = length(bytes),
      fingerprint = target_fp,
      runs_used = as.integer(runs) - budget$left
    )
  )
}

# What cannot be minimized, and why. Each of these would otherwise produce a
# confident but meaningless answer.
refuse_to_minimize <- function(recorded) {
  if (is.null(recorded)) {
    return("no sidecar: nothing records what this finding was")
  }
  if (is.null(recorded$fingerprint) || !nzchar(recorded$fingerprint)) {
    # Native crashes and timeouts have no R condition to fingerprint, so there
    # is no way to tell "the same bug" from "a different one".
    return("this finding has no fingerprint, so sameness cannot be checked")
  }
  if (identical(recorded$kind, "timeout")) {
    return("a timeout has no fingerprint to preserve while shrinking")
  }
  NULL
}

# Native findings reach the same gate by a different road, and deserve to be
# told why rather than handed the generic "no fingerprint" line. Both of these
# are recorded findings -- the artifact is real and worth keeping -- they just
# cannot be shrunk safely.
refuse_native_minimize <- function(native) {
  if (is.null(native)) {
    return(NULL)
  }
  if (identical(native$kind, "signal")) {
    return(paste(
      "this is a bare", native$signal_name %||% "signal",
      "with no sanitizer report: nothing describes the defect, so a smaller",
      "input that also dies cannot be shown to die of the same thing.",
      "Re-run under a sanitized build to get a report worth shrinking"
    ))
  }
  if (isTRUE(native$misconfigured)) {
    return(paste(
      "this is a LeakSanitizer report, which means detect_leaks=0 did not",
      "reach the process; fix the options rather than minimizing the leak"
    ))
  }
  NULL
}

# One candidate, one fresh process. The environment gate makes the child treat
# a *different* error as a normal run, so an accelerator that only knows
# "crashed or not" still cannot wander into another bug.
still_fails <- function(harness, bytes, target_fp, timeout, budget) {
  if (budget$left <= 0L) {
    return(FALSE)
  }
  budget$left <- budget$left - 1L

  path <- tempfile("zufuzz-candidate-")
  on.exit(unlink(path), add = TRUE)
  writeBin(bytes, path)

  result <- tryCatch(
    replay(harness, path, expect = target_fp, timeout = timeout),
    error = function(e) NULL
  )
  !is.null(result) && identical(result$outcome, "error") &&
    identical(result$fingerprint, target_fp)
}

# Delta debugging over the bytes: try removing ever-finer slices, keeping any
# removal that still fails the same way. Simple, engine-free, and it works on
# Windows -- which is the point of not delegating.
reduce_bytes <- function(harness, bytes, target_fp, timeout, budget) {
  n <- 2L
  while (length(bytes) >= 2L && budget$left > 0L) {
    size <- max(1L, length(bytes) %/% n)
    starts <- seq(1L, length(bytes), by = size)
    removed_any <- FALSE

    for (start in starts) {
      if (budget$left <= 0L) {
        break
      }
      end <- min(start + size - 1L, length(bytes))
      candidate <- bytes[-seq.int(start, end)]
      if (!length(candidate)) {
        next
      }
      if (still_fails(harness, candidate, target_fp, timeout, budget)) {
        bytes <- candidate
        removed_any <- TRUE
        n <- max(n - 1L, 2L)
        break
      }
    }

    if (!removed_any) {
      if (n >= length(bytes)) {
        break
      }
      n <- min(n * 2L, length(bytes))
    }
  }
  bytes
}

# afl-tmin does the same job far faster, and gets "same bug" wrong. It runs
# under the fingerprint gate so the child only dies on the right error, and
# whatever it produces is then checked and finished by the reducer above --
# so a wrong answer costs time, never correctness.
accelerated_candidate <- function(harness, finding, target_fp, timeout, budget,
                                  fallback) {
  if (!engine_available("afl")) {
    return(fallback)
  }
  out <- tempfile("zufuzz-tmin-")
  on.exit(unlink(out), add = TRUE)

  run <- afl_tool(
    "afl-tmin",
    c("-i", finding, "-o", out, "--", rscript_path(), "--vanilla", harness),
    timeout = timeout * 4,
    # The gate is what afl-tmin is missing. Under it the child treats any
    # *other* error as a normal run, so the tool's own "did it crash" test
    # cannot lead it into a different bug.
    env = c(ZUFUZZ_EXPECT_FINGERPRINT = target_fp)
  )
  if (is.null(run) || !file.exists(out)) {
    return(fallback)
  }
  candidate <- read_input(out)
  if (!length(candidate) || length(candidate) >= length(fallback)) {
    return(fallback)
  }
  if (still_fails(harness, candidate, target_fp, timeout, budget)) {
    return(candidate)
  }
  # It shrank into something else, which is exactly what it cannot be trusted
  # not to do.
  fallback
}

new_minimize_result <- function(original, minimized, refusal, stats) {
  structure(
    list(
      original = original,
      minimized = minimized,
      refused = refusal,
      stats = stats
    ),
    class = "zufuzz_minimize"
  )
}

#' @export
print.zufuzz_minimize <- function(x, ...) {
  if (!is.na(x$refused)) {
    cat("<zufuzz minimize> refused\n  ", x$refused, "\n", sep = "")
    return(invisible(x))
  }
  cat(sprintf(
    "<zufuzz minimize> %d -> %d bytes in %d run(s)\n",
    x$stats$original_bytes, x$stats$minimized_bytes, x$stats$runs_used
  ))
  cat(sprintf("  fingerprint %s (unchanged)\n", substr(x$stats$fingerprint, 1, 12)))
  cat(sprintf("  %s\n", x$minimized))
  invisible(x)
}
