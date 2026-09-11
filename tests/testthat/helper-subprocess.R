# Helpers for the tests that need a genuinely fresh R process.
#
# A child process can only `library(zufuzz)` if zufuzz is *installed*. Under
# `R CMD check` it is, which is what CI gates on; under `devtools::test()` the
# package is loaded from source by pkgload and no child can see it, so those
# tests skip with a reason rather than failing for an unrelated cause.

installed_zufuzz_lib <- function() {
  for (lib in .libPaths()) {
    if (dir.exists(file.path(lib, "zufuzz"))) {
      return(lib)
    }
  }
  NA_character_
}

child_env <- function(...) {
  extra <- c(...)
  env <- c(Sys.getenv(), ZUFUZZ_TEST_LIB = installed_zufuzz_lib())
  for (nm in names(extra)) {
    env[[nm]] <- extra[[nm]]
  }
  env
}

rscript_bin <- function() {
  file.path(
    R.home("bin"),
    if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript"
  )
}

run_rscript_expr <- function(code, ...) {
  res <- processx::run(
    rscript_bin(),
    c("--vanilla", "-e", code),
    env = child_env(...),
    error_on_status = FALSE,
    timeout = 120
  )
  trimws(res$stdout)
}

# Run a fixture harness over one input, in its own process, with findings
# directed somewhere disposable.
run_harness <- function(harness, input, artifact_dir, ...) {
  processx::run(
    rscript_bin(),
    c("--vanilla", harness, input),
    env = child_env(ZUFUZZ_ARTIFACT_DIR = artifact_dir, ...),
    error_on_status = FALSE,
    timeout = 120
  )
}

write_input <- function(bytes, dir = tempdir(), name = "input.bin") {
  path <- file.path(dir, name)
  dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
  writeBin(bytes, path)
  path
}
