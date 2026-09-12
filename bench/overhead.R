#!/usr/bin/env Rscript
# What instrumentation costs.
#
# Design section 14 asks for probe, provider and per-execution overhead
# measured *separately*, because they are paid at different rates: a probe on
# every branch, the provider once per input, the run loop once per input.
# Quoting a single "instrumentation overhead" number would hide which of the
# three you would actually be paying.
#
#   Rscript bench/overhead.R [reps]
#
# Two things this gets right that a naive timing does not, both learned by
# getting them wrong in bench/gate-b-packages.R:
#
#   Warm up first. R's JIT compiles a closure after a few calls, so the first
#   run of *anything* is slower. Timing a cold instrumented function against a
#   warm plain one -- or the reverse -- measures the JIT, not the probes. That
#   is how the Gate B script ended up showing instrumented code as "faster".
#
#   Report the median of many runs, not one. A single timing on a laptop with
#   other work running is noise with a decimal point.

suppressMessages(library(zufuzz))

reps <- as.integer(c(commandArgs(trailingOnly = TRUE), "31")[[1L]])

timeit <- function(expr, reps) {
  expr <- substitute(expr)
  env <- parent.frame()
  # Warm-up: enough calls that the JIT has compiled everything involved.
  for (i in 1:5) eval(expr, env)
  times <- numeric(reps)
  for (i in seq_len(reps)) {
    t0 <- proc.time()[["elapsed"]]
    eval(expr, env)
    times[[i]] <- proc.time()[["elapsed"]] - t0
  }
  stats::median(times)
}

# proc.time() resolves to roughly a millisecond. A measurement of a few
# milliseconds is mostly clock, so say so rather than printing a confident
# number derived from noise.
# A ratio is only meaningful when both sides do the same work. The provider
# row compares "build a provider and consume two values" against "slice a
# vector", which are different jobs -- printing 12x there would invite exactly
# the wrong conclusion.
report <- function(label, plain, instrumented, unit_n, comparable = TRUE) {
  if (instrumented < 0.05) {
    cat(sprintf("%-28s %9.4f %9.4f %9s %10s  (too fast to time reliably)\n",
                label, plain, instrumented, "-", "-"))
    return(invisible(NULL))
  }
  if (comparable && plain > 0) {
    cat(sprintf(
      "%-28s %9.4f %9.4f %8.2fx %10.2f\n",
      label, plain, instrumented, instrumented / plain,
      1e9 * (instrumented - plain) / unit_n
    ))
  } else {
    cat(sprintf(
      "%-28s %9s %9.4f %9s %10.2f\n",
      label, "-", instrumented, "-", 1e9 * instrumented / unit_n
    ))
  }
}

cat("zufuzz overhead\n")
cat(sprintf(
  "  %s, R %s.%s, %s\n  %d repetitions, median reported\n\n",
  Sys.info()[["sysname"]], R.version$major, R.version$minor,
  R.version$platform, reps
))
cat(sprintf("%-28s %9s %9s %9s %10s\n", "", "plain s", "instr s", "ratio", "ns/unit"))
cat(strrep("-", 70), "\n")

# -- 1. probe overhead ---------------------------------------------------

# Branch-heavy on purpose: this is the worst case, where nearly every
# statement is a probe site. Straight-line code pays proportionally less.
branchy <- function(n) {
  total <- 0L
  for (i in seq_len(n)) {
    if (i %% 2L == 0L) {
      total <- total + i
    } else if (i %% 3L == 0L) {
      total <- total - i
    } else {
      total <- total + 1L
    }
    if (total > 1000L) {
      total <- total %% 1000L
    }
  }
  total
}

iterations <- 300000L
plain_branchy <- timeit(branchy(iterations), reps)

uninstrument()
instrument("branchy")
sites <- instrumentation_report()$n_sites
instr_branchy <- timeit(branchy(iterations), reps)
uninstrument()

# Probes executed, not sites planted: a loop body is one site and many hits.
probes_executed <- iterations * 3
report("probe (branch-heavy)", plain_branchy, instr_branchy, probes_executed)
cat(sprintf("%-28s %d sites, ~%d probe executions per run\n\n", "", sites, probes_executed))

# -- 2. provider overhead ------------------------------------------------

bytes <- as.raw(rep(seq_len(255), length.out = 4096))

plain_read <- timeit(
  {
    for (i in 1:20000) {
      x <- as.integer(bytes[seq_len(64)])
    }
  },
  reps
)
provider_read <- timeit(
  {
    for (i in 1:20000) {
      fdp <- fuzzed_data_provider(bytes)
      x <- fdp$consume_int_in_range(1, 100)
      y <- fdp$consume_bytes(16)
    }
  },
  reps
)
report("provider (per input)", plain_read, provider_read, 20000, comparable = FALSE)

# -- 3. object generation ------------------------------------------------

spec <- r_object(types = c("integer", "character", "list"), max_len = 8, max_depth = 2)
gen <- timeit(
  {
    for (i in 1:2000) fuzzed_data_provider(bytes)$consume_object(spec)
  },
  reps
)
report("object generation", 0, gen, 2000, comparable = FALSE)

# -- 4. per-execution run-loop overhead ----------------------------------

corpus <- tempfile("bench-corpus-")
dir.create(corpus, recursive = TRUE)
for (i in 1:200) {
  writeBin(as.raw(rep(i %% 256, 32)), file.path(corpus, sprintf("in-%03d", i)))
}
artifacts <- tempfile("bench-art-")

noop <- function(data) NULL
loop <- timeit(
  fuzz(noop, args = corpus, engine = "none", quiet = TRUE, artifact_dir = artifacts),
  max(5L, reps %/% 3L)
)
report("run-once loop (per input)", 0, loop, 200, comparable = FALSE)

cat("\nNotes\n")
cat("  * ns/unit is nanoseconds of *added* cost per probe execution, per\n")
cat("    input, or per generated object -- whichever the row measures.\n")
cat("  * The probe row is the worst case: branch-heavy code where nearly\n")
cat("    every statement is a site. Straight-line code pays less.\n")
cat("  * Rows with a plain time of 0 have no uninstrumented counterpart;\n")
cat("    the instrumented column is the absolute cost.\n")
