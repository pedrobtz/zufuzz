# What makes two findings the same finding.
#
# A fingerprint has one job: decide whether the thing that just failed is the
# thing we were already looking at. It gates minimization (never shrink one
# bug into another), it is how replay() says "confirmed", and it is how two
# processes agree they found the same defect.
#
# It must therefore depend on the *defect* and not on the input. The obvious
# mistake is to include the originating call verbatim: a call usually carries
# the offending value, so every input would produce a new fingerprint and
# nothing would ever match anything.

fingerprint_version <- "1"

# `parse(text = x)` becomes "parse/1", `stop(msg)` becomes "stop/1". The
# function and its arity survive; the arguments -- which is where the fuzzed
# bytes live -- do not.
normalize_call <- function(cl) {
  if (is.null(cl)) {
    return("")
  }
  if (!is.call(cl)) {
    return(paste(utils::head(deparse(cl), 1L), collapse = ""))
  }
  head <- cl[[1L]]
  name <- if (is.name(head)) {
    as.character(head)
  } else if (is.call(head)) {
    # `pkg::fn(x)` and the like: keep the whole accessor, drop its arguments.
    paste(utils::head(deparse(head), 1L), collapse = "")
  } else {
    "<anonymous>"
  }
  paste0(name, "/", length(cl) - 1L)
}

# zufuzz's own frames, and R's condition machinery, say nothing about the
# target's defect. Their depth also changes with the execution model, so a
# traceback that kept them would differ between run-once and a campaign for
# reasons that have nothing to do with the bug.
zufuzz_frame_pattern <- paste0(
  "^(run_once|run_one_input|fuzz|invoke_target|with_torture|",
  "withCallingHandlers|tryCatch|tryCatchList|tryCatchOne|doTryCatch|",
  "\\.handleSimpleError|h\\(simpleError)\\b"
)

strip_zufuzz_frames <- function(calls) {
  if (!length(calls)) {
    return(character(0))
  }
  txt <- vapply(
    calls,
    function(x) paste(utils::head(deparse(x), 1L), collapse = ""),
    character(1)
  )
  txt[!grepl(zufuzz_frame_pattern, txt)]
}

#' Fingerprint an escaped R error
#'
#' @return A list with the parts and their digest. The parts are kept so a
#'   sidecar can show *why* two findings differ, not just that they do.
#' @noRd
fingerprint_condition <- function(cnd, kind = "r_error") {
  classes <- class(cnd)
  message <- conditionMessage(cnd)
  call_txt <- normalize_call(conditionCall(cnd))

  parts <- list(
    version = fingerprint_version,
    kind = kind,
    classes = classes,
    message = message,
    call = call_txt
  )
  parts$digest <- digest::digest(
    paste(
      c(fingerprint_version, kind, paste(classes, collapse = ","), message, call_txt),
      collapse = "\n"
    ),
    algo = "sha1",
    serialize = FALSE
  )
  parts
}

# A bounded traceback: enough to locate the defect, capped so a deep recursion
# cannot write a megabyte of sidecar. Truncation is marked rather than silent.
#
# `base_depth` is how deep the stack already was when zufuzz called the
# target. Everything above it belongs to whatever invoked zufuzz -- a harness,
# testthat, an IDE -- and putting twenty frames of that in a sidecar buries
# the one frame anybody wants to see.
bounded_traceback <- function(calls, limit = 20L, base_depth = 0L) {
  if (base_depth > 0L && length(calls) > base_depth) {
    calls <- calls[-seq_len(base_depth)]
  }
  txt <- strip_zufuzz_frames(calls)
  if (length(txt) <= limit) {
    return(txt)
  }
  c(
    utils::head(txt, limit),
    sprintf("... %d more frame(s) not recorded", length(txt) - limit)
  )
}

# Set by minimize() (Stage 7) and by any caller that wants an error to count
# only if it is *the* error. A mismatch is reported as a normal outcome, which
# is what keeps a minimizer from silently switching bugs.
expected_fingerprint <- function() {
  value <- Sys.getenv("ZUFUZZ_EXPECT_FINGERPRINT", unset = "")
  if (!nzchar(value)) NULL else value
}
