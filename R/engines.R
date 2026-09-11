# Which engines this machine can actually run, and where each was found.
#
# The point of reporting rather than discovering-at-failure: "why did my
# campaign not start" should be answerable before the campaign, in one call,
# with the command that would fix it.

# Where an engine can come from, in the order design section 3 resolves them.
engine_sources <- function(engine) {
  switch(engine,
    afl = list(
      option = "zufuzz.afl_path",
      env = "ZUFUZZ_AFL_PATH",
      binary = "afl-fuzz"
    ),
    list(option = NA_character_, env = NA_character_, binary = NA_character_)
  )
}

locate_engine <- function(engine) {
  src <- engine_sources(engine)

  from_option <- getOption(src$option)
  if (!is.null(from_option) && nzchar(from_option) && file.exists(from_option)) {
    return(list(path = from_option, how = paste0("option(", src$option, ")")))
  }

  if (!is.na(src$env)) {
    from_env <- Sys.getenv(src$env, unset = "")
    if (nzchar(from_env) && file.exists(from_env)) {
      return(list(path = from_env, how = paste0("$", src$env)))
    }
  }

  if (!is.na(src$binary)) {
    found <- Sys.which(src$binary)
    if (nzchar(found)) {
      return(list(path = unname(found), how = "PATH"))
    }
  }

  list(path = NA_character_, how = NA_character_)
}

install_hint <- function(engine) {
  if (.Platform$OS.type == "windows") {
    return("no campaign engine runs under Rtools; use WSL or a container")
  }
  switch(engine,
    afl = if (Sys.info()[["sysname"]] == "Darwin") {
      "brew install afl++"
    } else {
      "apt install afl++, or build from github.com/AFLplusplus/AFLplusplus"
    },
    libfuzzer = "provided by the zufuzz.libfuzzer companion package (not yet released)",
    NA_character_
  )
}

#' Which fuzzing engines are available
#'
#' zufuzz contains no engine. Instrumentation, the data provider, replay,
#' minimization and coverage reporting all work with none installed; running a
#' *campaign* needs one, and this says which are present.
#'
#' `"none"` is always available: it runs each listed input once, which is what
#' [replay()] and coverage reporting use.
#'
#' @return A data frame with one row per engine: whether it is available,
#'   where it was found, and what would install it.
#' @export
#' @examples
#' engines()
engines <- function() {
  known <- c("none", "afl", "libfuzzer")
  rows <- lapply(known, function(engine) {
    if (identical(engine, "none")) {
      return(data.frame(
        engine = engine, available = TRUE, found_at = "built in",
        how = "built in", hint = NA_character_, stringsAsFactors = FALSE
      ))
    }
    # The companion is not probed for until the release that ships it:
    # `R CMD check` warns about a call naming an undeclared package, and it
    # cannot be declared before it exists.
    if (identical(engine, "libfuzzer")) {
      return(data.frame(
        engine = engine, available = FALSE, found_at = NA_character_,
        how = NA_character_, hint = install_hint(engine), stringsAsFactors = FALSE
      ))
    }
    found <- locate_engine(engine)
    supported <- engine_supported(engine)
    data.frame(
      engine = engine,
      available = supported && !is.na(found$path),
      found_at = found$path,
      how = found$how,
      hint = if (!supported) {
        install_hint(engine)
      } else if (is.na(found$path)) {
        install_hint(engine)
      } else {
        NA_character_
      },
      stringsAsFactors = FALSE
    )
  })
  out <- do.call(rbind, c(rows, list(make.row.names = FALSE)))
  structure(out, class = c("zufuzz_engines", class(out)))
}

# An engine can be installed and still not usable here: AFL's worker protocol
# needs System V shared memory, which Rtools has none of.
engine_supported <- function(engine) {
  switch(engine,
    none = TRUE,
    afl = isTRUE(.Call(C_zufuzz_afl_supported)),
    libfuzzer = .Platform$OS.type != "windows",
    FALSE
  )
}

#' @rdname engines
#' @param engine Engine name.
#' @return `engine_available()` returns a single logical.
#' @export
engine_available <- function(engine) {
  tbl <- engines()
  row <- tbl[tbl$engine == engine, , drop = FALSE]
  if (!nrow(row)) {
    return(FALSE)
  }
  isTRUE(row$available[[1L]])
}

#' @export
print.zufuzz_engines <- function(x, ...) {
  cat("<zufuzz engines>\n")
  for (i in seq_len(nrow(x))) {
    mark <- if (isTRUE(x$available[[i]])) "yes" else " no"
    cat(sprintf("  %-10s %s", x$engine[[i]], mark))
    if (!is.na(x$found_at[[i]])) {
      cat(sprintf("   %s (%s)", x$found_at[[i]], x$how[[i]]))
    } else if (!is.na(x$hint[[i]])) {
      cat(sprintf("   %s", x$hint[[i]]))
    }
    cat("\n")
  }
  if (!any(x$available[x$engine != "none"])) {
    cat("  no campaign engine: instrument, generate, replay, minimize and\n")
    cat("  coverage all still work; fuzz(engine = \"none\") runs inputs once\n")
  }
  invisible(x)
}
