# Reading a sanitizer report out of a process that is already dead.
#
# When ASan or UBSan ends a run, no R code executes afterwards: there is no
# bridge left to write a sidecar, no condition to fingerprint, and no
# traceback. All that survives is text on stderr and a signal. This file turns
# that text back into the fields design section 10 asks for, so a native
# finding is described as well as an R error is.
#
# It parses; it does not run anything. That is deliberate -- every function
# here works on a log captured anywhere, by any engine, on any platform, which
# is what lets the whole thing be tested on a machine with no sanitizer at
# all.

sanitizer_report_version <- "1"

# The tools that announce themselves in a SUMMARY line, mapped to the `kind`
# recorded in a sidecar. LeakSanitizer is here to be *recognised*: zufuzz
# disables it (design section 10 -- R leaves allocations for the OS at exit on
# purpose), so a leak report means the options did not take effect, and
# reading it as an ordinary finding would send someone after R's own exit
# behaviour.
sanitizer_tools <- c(
  AddressSanitizer = "asan",
  HWAddressSanitizer = "asan",
  UndefinedBehaviorSanitizer = "ubsan",
  MemorySanitizer = "msan",
  ThreadSanitizer = "tsan",
  LeakSanitizer = "lsan"
)

# Frames that are never the defect.
#
# The sanitizer's own interceptors come first in almost every report -- frame
# #0 of a heap overflow is `__asan_memcpy`, which is true and useless. R's
# evaluator frames are next: every call from R into a package goes through
# them, so they are constant across findings and cannot distinguish two bugs.
# Dropping both is what leaves the first frame that belongs to the code under
# test.
sanitizer_runtime_frame <- paste0(
  "(^|[^[:alnum:]_])(__asan|__hwasan|__tsan|__msan|__ubsan|__sanitizer)",
  "|libclang_rt|libasan|libubsan|libtsan|libmsan",
  "|_?_interceptor_|^wrap_|GET_CALLER_PC"
)

# glibc's fortified string functions are inline wrappers in system headers, so
# an overflow through memcpy reports `memcpy string_fortified.h:29` *before*
# the caller that actually got the length wrong. That frame is byte identical
# for every memcpy overflow in every package, so a fingerprint built on it
# would merge unrelated defects into one bug. Found by the end-to-end check in
# docker/verify-sanitizer-path.R -- the only place a real glibc report appears,
# and not something any hand-written fixture would have shown.
libc_wrapper_frame <- paste0(
  "/usr/include/|/bits/|_fortified\\.h|/sysdeps/",
  # Bare interceptor names that arrive with no file of their own.
  "|^(mem|str|wmem|wcs)[a-z]+[[:space:]]"
)

r_runtime_frame <- paste0(
  "(^|[^[:alnum:]_])(Rf_|R_|do_|bcEval|Rprintf|Rvprintf)",
  "|libR\\.|libR-|R\\.framework|/src/main/|\\bRmain\\b|\\bmain\\b.*Rmain",
  "|^start\\+|\\(dyld:"
)

# `    #1 0x00010f1f8877 in main san.c:10`
# `    #0 0x00010f70d542 in __asan_memcpy+0xeb2 (libclang_rt...:x86_64h+0x9c542)`
# `    #2 0x7ff8118cc52f in start+0xbef (dyld:x86_64+0xfffffffffffde52f)`
sanitizer_frame_pattern <- "^\\s*#(\\d+)\\s+0x[0-9a-fA-F]+\\s+in\\s+(.*)$"

# Only the *first* stack. An ASan report carries several -- where the bad
# access happened, and separately where the memory was allocated or freed --
# and concatenating them produces a frame list that reads like one call stack
# but is not. The first block is the one that describes the defect.
parse_frames <- function(lines) {
  m <- regmatches(lines, regexec(sanitizer_frame_pattern, lines))
  keep <- vapply(m, length, integer(1)) == 3L
  if (!any(keep)) {
    return(character(0))
  }
  idx <- which(keep)
  # A stack is a contiguous run of frame lines; take up to the first gap.
  run_end <- which(diff(idx) != 1L)
  if (length(run_end)) {
    idx <- idx[seq_len(run_end[[1L]])]
  }
  trimws(vapply(m[idx], `[[`, character(1), 3L))
}

# The frames worth showing: the sanitizer's own machinery and R's evaluator
# removed, the rest capped. If *everything* was filtered we hand back the
# unfiltered head rather than nothing -- a report with no frames at all is
# worse than one with uninformative frames, and the filters are heuristics.
informative_frames <- function(frames, limit = 5L) {
  if (!length(frames)) {
    return(character(0))
  }
  kept <- frames[
    !grepl(sanitizer_runtime_frame, frames) &
      !grepl(libc_wrapper_frame, frames) &
      !grepl(r_runtime_frame, frames)
  ]
  if (!length(kept)) {
    kept <- frames
  }
  utils::head(kept, limit)
}

# SUMMARY is the one line every tool writes, and the two tools we care about
# write it differently:
#
#   SUMMARY: AddressSanitizer: heap-buffer-overflow san.c:10 in main
#   SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ub.c:2:55<space>
#
# UBSan has no ` in <function>` part and a trailing space. Requiring the
# function -- the obvious reading of the ASan line -- silently drops the
# location for every UBSan finding, so the function is optional here.
parse_summary <- function(line) {
  m <- regmatches(line, regexec(
    "^SUMMARY:\\s+([A-Za-z]+Sanitizer):\\s+(\\S+)\\s*(.*)$", line
  ))[[1L]]
  if (length(m) != 4L) {
    return(NULL)
  }
  rest <- trimws(m[[4L]])
  fn <- NA_character_
  location <- rest
  in_at <- regexec("^(.*?)\\s+in\\s+(.+)$", rest)
  parts <- regmatches(rest, in_at)[[1L]]
  if (length(parts) == 3L) {
    location <- trimws(parts[[2L]])
    fn <- trimws(parts[[3L]])
  }
  list(
    tool = m[[2L]],
    category = m[[3L]],
    location = if (nzchar(location)) location else NA_character_,
    fn = fn
  )
}

#' Parse a sanitizer report out of a captured log
#'
#' @param text The child's output. A character vector of lines or one string.
#' @return `NULL` when the log holds no report, otherwise a list with `kind`,
#'   `category`, `summary`, `location`, `function_name`, `top_frames` and
#'   `message`.
#' @noRd
parse_sanitizer_log <- function(text) {
  if (is.null(text) || !length(text)) {
    return(NULL)
  }
  lines <- unlist(strsplit(paste(text, collapse = "\n"), "\n", fixed = TRUE))
  if (!length(lines)) {
    return(NULL)
  }

  summaries <- grep("^SUMMARY:\\s+[A-Za-z]+Sanitizer:", lines)
  # A process can emit several reports before it dies -- UBSan without
  # halt_on_error keeps going. The first is the one to keep: later ones may be
  # consequences of it, and the first is what a re-run will hit again.
  if (!length(summaries)) {
    return(parse_sanitizer_log_without_summary(lines))
  }
  first <- summaries[[1L]]
  parsed <- parse_summary(lines[[first]])
  if (is.null(parsed)) {
    return(NULL)
  }

  kind <- unname(sanitizer_tools[parsed$tool])
  if (is.na(kind)) {
    kind <- "sanitizer"
  }

  # LeakSanitizer is a different animal. Its SUMMARY is a sentence
  # ("8 byte(s) leaked in 1 allocation(s).") rather than
  # "<category> <location> in <function>", so the generic parse yields
  # nonsense -- category "8". More to the point, zufuzz disables LSan on
  # purpose: R leaves allocations for the OS at exit, so a leak report means
  # the documented options did not reach the process. That is a configuration
  # fault to report, not a defect to fingerprint.
  if (identical(kind, "lsan")) {
    return(list(
      version = sanitizer_report_version,
      kind = "lsan",
      tool = parsed$tool,
      category = NA_character_,
      summary = trimws(lines[[first]]),
      location = NA_character_,
      function_name = NA_character_,
      message = paste(
        "LeakSanitizer reported a leak, which means detect_leaks=0 did not",
        "reach this process; R leaves allocations for the OS at exit, so",
        "these reports are noise rather than findings"
      ),
      misconfigured = TRUE,
      top_frames = informative_frames(parse_frames(lines[seq_len(first)]))
    ))
  }

  list(
    version = sanitizer_report_version,
    kind = kind,
    tool = parsed$tool,
    category = parsed$category,
    summary = trimws(lines[[first]]),
    location = parsed$location,
    function_name = parsed$fn,
    message = report_message(lines, first),
    top_frames = informative_frames(parse_frames(lines[seq_len(first)]))
  )
}

# UBSan reports the defect on its *first* line and only summarises afterwards;
# ASan puts it on the ==pid==ERROR line. Either is the human-readable half.
report_message <- function(lines, summary_index) {
  head_lines <- lines[seq_len(summary_index)]
  err <- grep("ERROR:\\s+[A-Za-z]+Sanitizer:", head_lines, value = TRUE)
  if (length(err)) {
    return(trimws(sub("^.*ERROR:\\s+", "", err[[1L]])))
  }
  runtime <- grep("runtime error:", head_lines, value = TRUE)
  if (length(runtime)) {
    return(trimws(runtime[[1L]]))
  }
  NA_character_
}

# A report whose SUMMARY never made it to disk: the log was truncated, or the
# process was killed mid-report. Recognising the ERROR line keeps the finding
# classified rather than filed as a bare signal, but there is no category to
# fingerprint on, so `category` stays NA and the fingerprint refuses.
parse_sanitizer_log_without_summary <- function(lines) {
  err <- grep("ERROR:\\s+[A-Za-z]+Sanitizer:", lines)
  if (!length(err)) {
    return(NULL)
  }
  tool <- sub("^.*ERROR:\\s+([A-Za-z]+Sanitizer):.*$", "\\1", lines[[err[[1L]]]])
  kind <- unname(sanitizer_tools[tool])
  list(
    version = sanitizer_report_version,
    kind = if (is.na(kind)) "sanitizer" else kind,
    tool = tool,
    category = NA_character_,
    summary = NA_character_,
    location = NA_character_,
    function_name = NA_character_,
    message = trimws(sub("^.*ERROR:\\s+", "", lines[[err[[1L]]]])),
    top_frames = informative_frames(parse_frames(lines)),
    truncated = TRUE
  )
}

# Fingerprint = kind + category + the top frame that belongs to the code under
# test (design section 10). Deliberately *not* the address, the pid, the shadow
# bytes or the offset: those change on every run of the same defect, and a
# fingerprint that changes per run matches nothing and gates nothing.
#
# Returns NULL when there is nothing stable to hash. That is what makes
# minimize() refuse a bare signal instead of shrinking one crash into another.
#' @noRd
fingerprint_sanitizer <- function(report) {
  if (is.null(report) || is.na(report$category %||% NA_character_)) {
    return(NULL)
  }
  frame <- if (length(report$top_frames)) report$top_frames[[1L]] else ""
  # A frame carries `+0x9c542` offsets and absolute paths that move between
  # builds; the symbol is the part that means something.
  frame <- sub("\\+0x[0-9a-fA-F]+.*$", "", frame)
  frame <- sub("\\s*\\(.*\\)$", "", frame)
  # `zujson_decode_utf8 /src/zujson/src/utf8.c:204` -> keep the file, drop the
  # directory. The same defect built in a different tree -- a container, a
  # reviewer's checkout -- must fingerprint the same, or every confirmed
  # reproduction would be reported as a different bug.
  frame <- sub("(^|[[:space:]])/[^[:space:]]*/([^/[:space:]]+)$", "\\1\\2", frame)
  parts <- list(
    version = sanitizer_report_version,
    kind = report$kind,
    classes = c(report$kind, report$category),
    message = report$summary %||% NA_character_,
    call = trimws(frame)
  )
  parts$digest <- digest::digest(
    paste(c(
      sanitizer_report_version, report$kind, report$category, trimws(frame)
    ), collapse = "\n"),
    algo = "sha1", serialize = FALSE
  )
  parts
}

# What killed the child, in the words a sidecar uses. Signals only mean
# anything on Unix; processx reports them the same way a shell does.
#' @noRd
death_by_signal <- function(status) {
  if (is.null(status) || length(status) != 1L || is.na(status)) {
    return(NA_integer_)
  }
  status <- as.integer(status)
  if (status > 128L && status < 192L) {
    return(status - 128L)
  }
  if (status < 0L) {
    return(-status)
  }
  NA_integer_
}

signal_names <- c(
  "2" = "SIGINT", "4" = "SIGILL", "6" = "SIGABRT", "8" = "SIGFPE",
  "9" = "SIGKILL", "10" = "SIGBUS", "11" = "SIGSEGV", "15" = "SIGTERM"
)

#' Describe how a child died, sanitizer report or not
#'
#' The distinction that matters: a report is a *described* defect and can be
#' fingerprinted; a bare signal is a death with no description, which design
#' section 10 says to record but never fingerprint.
#'
#' @noRd
native_finding <- function(log, status = NA_integer_) {
  report <- parse_sanitizer_log(log)
  signal <- death_by_signal(status)
  if (!is.null(report)) {
    report$signal <- signal
    report$signal_name <- unname(signal_names[as.character(signal)]) %||% NA_character_
    report$status <- if (is.na(status)) NA_integer_ else as.integer(status)
    return(report)
  }
  if (is.na(signal)) {
    return(NULL)
  }
  list(
    version = sanitizer_report_version,
    kind = "signal",
    tool = NA_character_,
    category = NA_character_,
    summary = NA_character_,
    location = NA_character_,
    function_name = NA_character_,
    # Nothing in a bare signal says what went wrong; saying so plainly is more
    # useful than a confident-looking record with empty fields.
    message = sprintf(
      "died on %s with no sanitizer report",
      unname(signal_names[as.character(signal)]) %||% paste("signal", signal)
    ),
    top_frames = character(0),
    signal = signal,
    signal_name = unname(signal_names[as.character(signal)]) %||% NA_character_,
    status = if (is.na(status)) NA_integer_ else as.integer(status)
  )
}

# ---------------------------------------------------------------------------
# Is this process actually sanitized?
#
# The failure this prevents: a sanitized campaign that quietly was not one.
# Nothing about an unsanitized run *looks* wrong -- it finds fewer bugs and
# exits zero -- so "we fuzzed it under ASan" becomes a claim nobody checked.
# Design section 10 says to report the run as unsanitized rather than let it
# pass silently, which requires being able to tell.

# The documented option sets (design section 10), with the reason each one is
# there. They are defaults to pass to a child, not something zufuzz sets for
# itself: zufuzz never owns a sanitizer.
#' @noRd
sanitizer_options <- function() {
  c(
    # detect_leaks=0: R leaves allocations for the OS at exit on purpose, so
    #   LSan reports are noise that buries real findings.
    # allocator_may_return_null=1: lets R's own out-of-memory path run instead
    #   of ASan aborting, so a huge allocation is an R error, not a finding.
    # abort_on_error=1: ends a report in SIGABRT, which is what every engine
    #   recognises as a crash. Without it ASan exits 1 and AFL records nothing.
    ASAN_OPTIONS = "detect_leaks=0:alloc_dealloc_mismatch=0:allocator_may_return_null=1:abort_on_error=1",
    UBSAN_OPTIONS = "print_stacktrace=1:halt_on_error=1"
  )
}

# Definitive evidence, and only on Linux: the sanitizer runtime is mapped into
# this process. Configuration A (sanitized R) and Configuration B (preloaded
# runtime) both show up here, which is the point -- it answers "is the runtime
# present", not "how did it get here".
maps_evidence <- function(maps = "/proc/self/maps") {
  if (!file.exists(maps)) {
    return(NULL)
  }
  lines <- tryCatch(readLines(maps, warn = FALSE), error = function(e) character(0))
  if (!length(lines)) {
    return(NULL)
  }
  found <- c(
    asan = any(grepl("libasan|libclang_rt\\.asan|libclang_rt\\.hwasan", lines)),
    ubsan = any(grepl("libubsan|libclang_rt\\.ubsan", lines)),
    tsan = any(grepl("libtsan|libclang_rt\\.tsan", lines)),
    msan = any(grepl("libmsan|libclang_rt\\.msan", lines))
  )
  names(found)[found]
}

# How R was configured to build packages. This is a *proxy*: it says the
# toolchain would compile a package with sanitizers, not that this process has
# the runtime. Reported separately for exactly that reason.
makevars_evidence <- function() {
  flags <- tryCatch(
    vapply(
      c("CFLAGS", "CXXFLAGS", "LDFLAGS"),
      function(v) paste(system2(file.path(R.home("bin"), "R"),
        c("CMD", "config", v),
        stdout = TRUE, stderr = FALSE
      ), collapse = " "),
      character(1)
    ),
    error = function(e) character(0),
    warning = function(w) character(0)
  )
  if (!length(flags)) {
    return(character(0))
  }
  hit <- grepl("-fsanitize=", flags)
  if (!any(hit)) {
    return(character(0))
  }
  san <- regmatches(flags[hit], regexpr("-fsanitize=[^ ]+", flags[hit]))
  unique(unlist(strsplit(sub("^-fsanitize=", "", san), ",", fixed = TRUE)))
}

#' What sanitizer, if any, is in effect
#'
#' @return A `zufuzz_sanitizer_status`: `sanitized` is TRUE only on definitive
#'   evidence that the runtime is mapped into this process. `evidence` says
#'   what was actually observed and how, because "probably" is not something a
#'   campaign report should round up to "yes".
#' @noRd
sanitizer_status <- function() {
  mapped <- maps_evidence()
  configured <- makevars_evidence()
  preload <- Sys.getenv("LD_PRELOAD", unset = "")
  insert <- Sys.getenv("DYLD_INSERT_LIBRARIES", unset = "")

  evidence <- character(0)
  if (!is.null(mapped) && length(mapped)) {
    evidence <- c(evidence, sprintf(
      "runtime mapped into this process: %s", paste(mapped, collapse = ", ")
    ))
  }
  if (length(configured)) {
    evidence <- c(evidence, sprintf(
      "R builds packages with -fsanitize=%s", paste(configured, collapse = ",")
    ))
  }
  for (v in c(LD_PRELOAD = preload, DYLD_INSERT_LIBRARIES = insert)) {
    if (nzchar(v) && grepl("asan|ubsan|tsan|msan|sanitiz", v, ignore.case = TRUE)) {
      evidence <- c(evidence, sprintf("preloaded: %s", v))
    }
  }

  structure(
    list(
      # Only /proc/self/maps proves the runtime is here. Build flags say what
      # the compiler would do; a preload variable says what was asked for.
      # Neither is proof, and treating them as proof is the silent pass this
      # function exists to prevent.
      sanitized = !is.null(mapped) && length(mapped) > 0L,
      sanitizers = if (is.null(mapped)) character(0) else mapped,
      # NA rather than FALSE where the question cannot be answered: macOS and
      # Windows have no /proc, so "not detected" there means "unknown", and
      # reporting it as "definitely unsanitized" would be its own false claim.
      detectable = file.exists("/proc/self/maps"),
      configured = configured,
      evidence = evidence,
      options = sanitizer_options()
    ),
    class = "zufuzz_sanitizer_status"
  )
}

#' @export
print.zufuzz_sanitizer_status <- function(x, ...) {
  cat("<zufuzz sanitizer status>\n")
  state <- if (x$sanitized) {
    paste0("sanitized (", paste(x$sanitizers, collapse = ", "), ")")
  } else if (!x$detectable) {
    "unknown -- this platform has no /proc/self/maps to read"
  } else {
    "not sanitized"
  }
  cat("  ", state, "\n", sep = "")
  if (length(x$evidence)) {
    for (e in x$evidence) cat("   - ", e, "\n", sep = "")
  }
  if (!x$sanitized) {
    cat("   findings will be limited to crashes and R errors;\n")
    cat("   see vignette(\"sanitizers\", package = \"zufuzz\")\n")
  }
  invisible(x)
}
