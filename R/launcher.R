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
  if (identical(resolved, "afl")) {
    return(run_afl_campaign(
      harness = path, corpus = corpus, args = args, dots = list(...),
      time_limit = time_limit, runs = runs,
      artifact_dir = artifact_dir %||% tempfile("zufuzz-artifacts-"),
      env = env, quiet = quiet
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
  # Length-checked: `nzchar(character(0))` is logical(0), and `&&` on a
  # zero-length operand is an error in current R. A print method that can
  # throw is the worst place for this -- it fails while you are trying to
  # look at what went wrong.
  if (identical(x$stop_reason, "infrastructure") &&
      length(x$stderr) && nzchar(x$stderr[[1L]])) {
    cat("  ", utils::tail(strsplit(x$stderr[[1L]], "\n")[[1L]], 3L), sep = "\n  ")
    cat("\n")
  }
  invisible(x)
}

# -- the AFL campaign ----------------------------------------------------

# AFL's options are `-x file` pairs, not libFuzzer's `-name=value`. Mapping
# them by hand rather than passing anything through means an unsupported flag
# is refused with the list of what works, instead of reaching afl-fuzz and
# failing there with its own vocabulary.
afl_flag_map <- c(
  dict = "-x",
  timeout = "-t",
  memory = "-m",
  seed = "-s",
  power = "-p"
)

afl_flag_arguments <- function(dots) {
  if (!length(dots)) {
    return(character(0))
  }
  nms <- names(dots)
  if (is.null(nms) || any(!nzchar(nms))) {
    stop("zufuzz: engine flags must be named", call. = FALSE)
  }
  unknown <- setdiff(nms, names(afl_flag_map))
  if (length(unknown)) {
    stop(
      "zufuzz: afl-fuzz has no option for ",
      paste(sQuote(unknown), collapse = ", "),
      "; supported: ", paste(names(afl_flag_map), collapse = ", "),
      call. = FALSE
    )
  }
  unlist(lapply(nms, function(nm) {
    c(afl_flag_map[[nm]], as.character(dots[[nm]]))
  }), use.names = FALSE)
}

afl_command <- function(afl, corpus, out_dir, harness, args, dots,
                        time_limit, runs) {
  argv <- c("-i", corpus, "-o", out_dir)
  # -V is a wall-clock budget and -E an execution budget; both make afl-fuzz
  # exit by itself, which is what turns a campaign into something CI can run.
  if (is.finite(time_limit)) {
    argv <- c(argv, "-V", format(time_limit, scientific = FALSE))
  }
  if (is.finite(runs)) {
    argv <- c(argv, "-E", format(runs, scientific = FALSE))
  }
  argv <- c(argv, afl_flag_arguments(dots))
  c(argv, "--", rscript_path(), "--vanilla", harness, args)
}

run_afl_campaign <- function(harness, corpus, args, dots, time_limit, runs,
                             artifact_dir, env, quiet) {
  afl <- locate_engine("afl")$path
  if (is.na(afl)) {
    return(infrastructure_result("afl", "afl-fuzz was not found; see engines()"))
  }
  if (is.null(corpus) || !dir.exists(corpus)) {
    # afl-fuzz refuses to start without seeds, and its own message is about
    # directories rather than about what the caller forgot.
    return(infrastructure_result(
      "afl", "engine \"afl\" needs a corpus directory with at least one seed"
    ))
  }

  dir.create(artifact_dir, recursive = TRUE, showWarnings = FALSE)
  out_dir <- file.path(artifact_dir, "afl")
  dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)
  before <- artifact_inventory(artifact_dir)

  child_env <- c(
    Sys.getenv(),
    ZUFUZZ_ARTIFACT_DIR = artifact_dir,
    R_NO_SEGV_HANDLER = "1",
    # The target is Rscript, not an afl-cc-instrumented binary; without this
    # afl-fuzz refuses to run it at all. This is what python-afl's launcher
    # does too.
    AFL_SKIP_BIN_CHECK = "1",
    # No terminal in CI, and the full-screen UI corrupts a captured log.
    AFL_NO_UI = "1",
    # A CI runner has no cpufreq governor to tune, and AFL otherwise refuses
    # to start rather than running slightly slower.
    AFL_SKIP_CPUFREQ = "1",
    # A campaign that finds something should keep going; the artifacts are
    # the result, not a reason to stop.
    AFL_IGNORE_PROBLEMS = "1"
  )
  for (nm in names(env)) {
    child_env[[nm]] <- env[[nm]]
  }

  started <- Sys.time()
  run <- tryCatch(
    processx::run(
      afl,
      afl_command(afl, corpus, out_dir, harness, args, dots, time_limit, runs),
      env = child_env,
      error_on_status = FALSE,
      timeout = if (is.finite(time_limit)) time_limit * 3 + 60 else Inf
    ),
    interrupt = function(cnd) structure(list(interrupted = TRUE), class = "zufuzz_interrupted")
  )
  elapsed <- as.numeric(difftime(Sys.time(), started, units = "secs"))

  if (inherits(run, "zufuzz_interrupted")) {
    return(new_result(
      engine = "afl", stop_reason = "interrupted", findings = list(),
      elapsed = elapsed, artifact_dir = artifact_dir, quiet = quiet
    ))
  }

  import_afl_findings(out_dir, artifact_dir)
  findings <- collect_findings(artifact_dir, before)

  new_result(
    engine = "afl",
    stop_reason = classify_run(run, findings),
    findings = findings,
    elapsed = elapsed,
    artifact_dir = artifact_dir,
    status = run$status,
    stdout = run$stdout,
    stderr = run$stderr,
    timed_out = isTRUE(run$timeout),
    quiet = quiet
  )
}

# AFL names its findings `id:000000,sig:06,...`; zufuzz names everything
# `crash-<sha1>` so that an artifact means the same thing whichever engine
# produced it. The import copies rather than moves, leaving AFL's directory
# untouched so afl-cmin, afl-tmin and afl-whatsup keep working on it.
import_afl_findings <- function(out_dir, artifact_dir) {
  imported <- character(0)
  for (kind in c("crashes", "hangs")) {
    # Single-instance runs land in <out>/default/; -M/-S runs in <out>/<name>/.
    dirs <- c(
      file.path(out_dir, kind),
      Sys.glob(file.path(out_dir, "*", kind))
    )
    for (dir in dirs[dir.exists(dirs)]) {
      for (src in list.files(dir, pattern = "^id:", full.names = TRUE)) {
        bytes <- read_input(src)
        prefix <- if (identical(kind, "crashes")) "crash" else "timeout"
        dest <- file.path(artifact_dir, artifact_name(bytes, prefix))
        if (!file.exists(dest)) {
          writeBin(bytes, dest)
        }
        if (!file.exists(paste0(dest, ".json"))) {
          # A finding the child could not describe -- a native crash, or a
          # hang -- still gets a sidecar, so every artifact has one and
          # downstream tooling need not special-case.
          jsonlite::write_json(
            new_sidecar(bytes, kind = prefix, engine = "afl"),
            paste0(dest, ".json"),
            auto_unbox = TRUE, null = "null", pretty = TRUE
          )
        }
        imported <- c(imported, dest)
      }
    }
  }
  invisible(imported)
}

#' Thin wrappers over AFL's corpus and test-case minimizers
#'
#' Used by [minimize()] as accelerators. They are AFL's tools, run as AFL
#' documents them; zufuzz only supplies the command line.
#'
#' @noRd
afl_tool <- function(tool, args, timeout = 300, env = character()) {
  path <- Sys.which(tool)
  if (!nzchar(path)) {
    return(NULL)
  }
  child_env <- c(
    Sys.getenv(),
    AFL_SKIP_BIN_CHECK = "1",
    AFL_NO_UI = "1",
    AFL_SKIP_CPUFREQ = "1",
    R_NO_SEGV_HANDLER = "1"
  )
  for (nm in names(env)) {
    child_env[[nm]] <- env[[nm]]
  }
  processx::run(
    unname(path), args,
    env = child_env,
    error_on_status = FALSE,
    timeout = timeout
  )
}
