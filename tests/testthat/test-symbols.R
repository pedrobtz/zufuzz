# The Stage 0 gate (roadmap) and the layering rule (design section 15), in one
# test.
#
# zufuzz's shared object must not be able to end the R process, signal it,
# write to its standard streams, or reference a fuzzing-engine or sanitizer
# symbol. Code that genuinely needs any of those belongs in the
# zufuzz.libfuzzer companion package, which is distributed outside CRAN.
#
# Checking the built object rather than the sources also catches a forbidden
# call reached through a header or an inline function, and it is the same
# evidence `R CMD check --as-cran` uses when it decides whether to raise the
# "compiled code calls ..." NOTE.

# Deliberately absent from this list:
#   write, fork, waitpid -- the AFL fork server (Stage 6) writes protocol
#   bytes to file descriptors 198/199 and forks the worker. Those are not
#   writes to R's standard streams, which is what the rule is about, so the
#   stdio family below is forbidden and the raw descriptor calls are not.
forbidden_exact <- c(
  # end the process
  "exit", "_exit", "_Exit", "abort", "quick_exit",
  # signal it: a crash is raised from R with tools::pskill(), never from C
  "raise", "kill", "pthread_kill",
  # write to the standard streams
  "printf", "fprintf", "vprintf", "vfprintf", "perror",
  "puts", "fputs", "putchar", "fputc", "fwrite",
  # hand control to another program
  "system", "popen", "execl", "execv", "execvp", "execve"
)

forbidden_prefixes <- c(
  "__sanitizer_", "__asan_", "__msan_", "__ubsan_", "__tsan_", "LLVMFuzzer"
)

zufuzz_dll_path <- function() {
  dll <- getLoadedDLLs()[["zufuzz"]]
  if (is.null(dll)) {
    return(NA_character_)
  }
  dll[["path"]]
}

# Undefined (imported) symbols of a shared object, normalised to their C
# names. Both `nm` spellings are tried because a shared object's undefined
# symbols live in the dynamic table on Linux, while macOS reports them from
# the ordinary one.
undefined_symbols <- function(path) {
  nm <- Sys.which("nm")
  if (!nzchar(nm)) {
    return(NULL)
  }

  lines <- character()
  for (flags in list(c("-D", "--undefined-only"), "-u")) {
    out <- suppressWarnings(
      system2(nm, c(flags, shQuote(path)), stdout = TRUE, stderr = FALSE)
    )
    if (is.null(attr(out, "status"))) {
      lines <- c(lines, out)
    }
  }
  if (!length(lines)) {
    return(NULL)
  }

  lines <- trimws(lines)
  lines <- lines[nzchar(lines)]
  syms <- vapply(
    strsplit(lines, "[[:space:]]+"),
    function(x) x[[length(x)]],
    character(1)
  )
  # Drop glibc version suffixes (memcpy@GLIBC_2.14) and the single leading
  # underscore Mach-O adds to every C symbol.
  syms <- sub("@.*$", "", syms)
  if (identical(Sys.info()[["sysname"]], "Darwin")) {
    syms <- sub("^_", "", syms)
  }
  unique(syms)
}

test_that("the shared object cannot terminate R or write to its streams", {
  path <- zufuzz_dll_path()
  skip_if(is.na(path), "zufuzz DLL is not loaded")
  skip_if_not(nzchar(Sys.which("nm")), "nm is not available")

  syms <- undefined_symbols(path)
  skip_if(is.null(syms) || !length(syms), "nm reported no symbols")

  # Guard against the check silently passing because parsing broke: a real R
  # package always imports something from R itself.
  expect_true(any(startsWith(syms, "R_") | startsWith(syms, "Rf_")))

  expect_equal(intersect(syms, forbidden_exact), character(0))
})

test_that("the shared object references no engine or sanitizer symbol", {
  path <- zufuzz_dll_path()
  skip_if(is.na(path), "zufuzz DLL is not loaded")
  skip_if_not(nzchar(Sys.which("nm")), "nm is not available")

  syms <- undefined_symbols(path)
  skip_if(is.null(syms) || !length(syms), "nm reported no symbols")

  matched <- unlist(lapply(
    forbidden_prefixes,
    function(p) syms[startsWith(syms, p)]
  ))
  expect_equal(as.character(matched), character(0))
})
