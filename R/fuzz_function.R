# The one-liner over a package function.
#
# `fuzz(zujson::parse, corpus = "corpus")` cannot work as written: the target
# receives raw bytes, `corpus` is a positional engine argument, and a campaign
# ends the calling process. The intent is reasonable, so it gets a function
# that generates the harness it implies and runs that instead.

# Catching one of these would catch everything, including the defects the
# campaign exists to find. `expect` names what the function may legitimately
# raise for bad input, so it has to be specific.
generic_condition_classes <- c("error", "simpleError", "condition", "simpleCondition")

#' Fuzz a single function
#'
#' Generates a harness around `fn` and runs it through [fuzz_file()]. The
#' generated script is kept, and its path reported, so a one-liner that finds
#' something can be promoted into a real harness.
#'
#' @param fn The function to fuzz. A function from a package namespace is
#'   referred to by name and re-resolved in the child; any other closure is
#'   serialized.
#' @param corpus Corpus directory.
#' @param ... Passed to [fuzz_file()].
#' @param input `"raw"` passes the bytes; `"string"` passes text decoded from
#'   them.
#' @param expect Condition classes `fn` may legitimately raise for bad input.
#'   Caught narrowly around the call. Generic classes are rejected.
#' @param instrument Package to instrument; defaults to `fn`'s own package.
#' @param harness_out Where to write the generated harness. A temporary file
#'   by default.
#' @return A `zufuzz_result`, with the harness path in `$harness`.
#' @export
fuzz_function <- function(fn, corpus = NULL, ..., input = c("raw", "string"),
                          expect = character(), instrument = NULL,
                          harness_out = NULL) {
  input <- match.arg(input)
  fn_expr <- substitute(fn)

  if (!is.function(fn)) {
    stop("zufuzz: `fn` must be a function", call. = FALSE)
  }
  bad <- intersect(expect, generic_condition_classes)
  if (length(bad)) {
    stop(
      "zufuzz: `expect` must name specific condition classes; ",
      paste(sQuote(bad), collapse = ", "),
      " would catch the defects the campaign is looking for",
      call. = FALSE
    )
  }

  spec <- describe_target(fn, fn_expr)
  if (!is.null(spec$error)) {
    return(infrastructure_result("none", spec$error))
  }

  harness_out <- harness_out %||% tempfile("zufuzz-harness-", fileext = ".R")
  writeLines(
    harness_source(spec, input = input, expect = expect, instrument = instrument),
    harness_out
  )

  result <- fuzz_file(harness_out, corpus = corpus, ...)
  result$harness <- harness_out
  result
}

# A namespace function travels as a name; anything else has to be serialized,
# and serialization is where a closure quietly loses the globals it depends
# on.
describe_target <- function(fn, fn_expr) {
  env <- environment(fn)
  if (is.environment(env) && isNamespace(env)) {
    pkg <- environmentName(env)
    name <- binding_name_in(fn, env)
    if (!is.na(name)) {
      return(list(kind = "name", pkg = pkg, name = name))
    }
  }

  orphans <- globals_lost_by_serialization(fn)
  if (length(orphans)) {
    # Caught here rather than in the child, where it would surface as an
    # ordinary error inside the target and be reported as a finding -- sending
    # someone to debug a defect that does not exist.
    return(list(error = paste0(
      "this closure refers to ",
      paste(sQuote(orphans), collapse = ", "),
      " in the global environment, which will not exist in the child process. ",
      "Move it into a package, or write a harness script."
    )))
  }

  path <- tempfile("zufuzz-target-", fileext = ".rds")
  saveRDS(fn, path)
  list(kind = "object", path = path)
}

binding_name_in <- function(fn, env) {
  for (nm in ls(env, all.names = TRUE)) {
    value <- tryCatch(get(nm, envir = env, inherits = FALSE), error = function(e) NULL)
    if (is.function(value) && identical(value, fn)) {
      return(nm)
    }
  }
  NA_character_
}

# R does not serialize the global environment with a closure, so anything the
# closure resolves *there* is gone in the child. Anything it resolves in a
# package or in its own enclosure travels fine.
globals_lost_by_serialization <- function(fn) {
  globals <- tryCatch(
    codetools::findGlobals(fn, merge = TRUE),
    error = function(e) character(0)
  )
  if (!length(globals)) {
    return(character(0))
  }
  env <- environment(fn)
  if (!is.environment(env)) {
    return(character(0))
  }
  lost <- vapply(globals, function(g) {
    where <- env
    while (!identical(where, emptyenv())) {
      if (exists(g, envir = where, inherits = FALSE)) {
        return(identical(where, globalenv()))
      }
      where <- parent.env(where)
    }
    FALSE
  }, logical(1))
  globals[lost]
}

# How raw bytes become the argument the target actually takes.
#
# Its own function so it can be tested by evaluating it, rather than by
# grepping it out of generated text -- a decoder that errors on some byte
# sequence would report a defect in the harness rather than in the target, so
# "never errors" needs a real test.
#
# Inlined rather than calling fuzzed_data_provider(), which arrives in Stage 8:
# the generated harness stays self-contained and explicit about what it does.
input_adapter_lines <- function(input) {
  if (identical(input, "raw")) {
    return("value <- data")
  }
  c(
    "value <- rawToChar(data[data != as.raw(0)])",
    "Encoding(value) <- \"UTF-8\"",
    "if (!isTRUE(validUTF8(value))) {",
    "  value <- iconv(value, \"UTF-8\", \"UTF-8\", sub = \"\")",
    "}"
  )
}

harness_source <- function(spec, input, expect, instrument) {
  resolve <- if (identical(spec$kind, "name")) {
    sprintf(
      'target_fn <- get(%s, envir = asNamespace(%s), inherits = FALSE)',
      encodeString(spec$name, quote = '"'), encodeString(spec$pkg, quote = '"')
    )
  } else {
    sprintf("target_fn <- readRDS(%s)", encodeString(spec$path, quote = '"'))
  }

  to_instrument <- instrument %||% (if (identical(spec$kind, "name")) spec$pkg else NULL)
  instrument_line <- if (is.null(to_instrument)) {
    "# nothing to instrument: the target is not a package function"
  } else {
    sprintf("instrument_package(%s)", encodeString(to_instrument, quote = '"'))
  }

  adapt <- input_adapter_lines(input)

  # Expected rejections are caught around the call and only the call. Wrapping
  # the whole body would swallow the defects too.
  call_line <- if (length(expect)) {
    sprintf(
      "tryCatch(target_fn(value), %s)",
      paste(sprintf(
        "%s = function(cnd) NULL",
        vapply(expect, function(x) encodeString(x, quote = "`"), character(1))
      ), collapse = ", ")
    )
  } else {
    "target_fn(value)"
  }

  c(
    "# Generated by zufuzz::fuzz_function(). Edit freely: this is an ordinary",
    "# harness, and promoting it into one is the point.",
    "library(zufuzz)",
    "",
    resolve,
    instrument_line,
    "",
    "test_one_input <- function(data) {",
    paste0("  ", adapt),
    paste0("  ", call_line),
    "  invisible(NULL)",
    "}",
    "",
    "fuzz(test_one_input, engine = \"none\", quiet = TRUE)"
  )
}
