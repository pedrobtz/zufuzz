#!/usr/bin/env Rscript
# Gate B, the part that needs no engine: does instrumenting a real package
# change what it does?
#
# The transformation is supposed to be invisible. The unit tests prove that on
# fixtures designed to exercise each rule; this proves it on code nobody wrote
# with zufuzz in mind. Run one package per process, so a package that breaks
# cannot take the others' results with it.
#
#   Rscript bench/gate-b-packages.R <package>
#
# Prints one line of TSV: package, closures, sites, topics, topics that were
# not reproducible even uninstrumented, real mismatches, plain seconds,
# instrumented seconds.

args <- commandArgs(trailingOnly = TRUE)
if (!length(args)) stop("usage: gate-b-packages.R <package>")
pkg <- args[[1L]]

library(zufuzz)
suppressMessages(library(pkg, character.only = TRUE))

# Documented examples are the closest thing to "the package's own tests" that
# survives installation, and they exercise the paths the author thought were
# worth showing.
topics <- function(p) {
  db <- tryCatch(tools::Rd_db(p), error = function(e) list())
  if (!length(db)) return(character(0))
  vapply(names(db), function(f) sub("\\.Rd$", "", f), character(1), USE.NAMES = FALSE)
}

run_examples <- function(p, tops) {
  out <- character(length(tops))
  for (i in seq_along(tops)) {
    out[[i]] <- paste(capture.output(
      tryCatch(
        suppressWarnings(suppressMessages(
          utils::example(tops[[i]], package = p, character.only = TRUE,
                         echo = FALSE, give.lines = FALSE, local = TRUE)
        )),
        error = function(e) cat("ERROR:", conditionMessage(e), "\n")
      ),
      type = "output"
    ), collapse = "\n")
  }
  out
}

wd <- file.path(tempdir(), "gate-b")
dir.create(wd, recursive = TRUE, showWarnings = FALSE)
setwd(wd)

tops <- topics(pkg)
if (!length(tops)) {
  cat(sprintf("%s\tNA\tNA\t0\tNA\tNA\tNA\n", pkg))
  quit(save = "no")
}

# Control arm first. Some examples print a tempfile path, a timezone or a
# library path, and differ between two *identical* runs. Without this, those
# would be reported as "instrumentation changed the package", which is false
# and is exactly the kind of claim that wastes an afternoon.
t0 <- proc.time()[["elapsed"]]
before <- run_examples(pkg, tops)
t_plain <- proc.time()[["elapsed"]] - t0
control <- run_examples(pkg, tops)

stable <- before == control
tops_stable <- tops[stable]
unstable <- sum(!stable)

report <- instrument_package(pkg)

t0 <- proc.time()[["elapsed"]]
after <- run_examples(pkg, tops)
t_inst <- proc.time()[["elapsed"]] - t0

# Compare only what was reproducible to begin with.
mismatches <- sum(before[stable] != after[stable])
cat(sprintf(
  "%s\t%d\t%d\t%d\t%d\t%d\t%.2f\t%.2f\n",
  pkg, report$n_functions, report$n_sites, length(tops), unstable, mismatches,
  t_plain, t_inst
))

if (mismatches > 0) {
  idx <- which(stable & before != after)
  for (i in utils::head(idx, 3L)) {
    cat("MISMATCH in topic:", tops[[i]], "\n", file = stderr())
  }
}
