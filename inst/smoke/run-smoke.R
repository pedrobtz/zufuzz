#!/usr/bin/env Rscript
# Bounded, seeded, and it fails loudly rather than passing quietly.
#
# The failure mode worth guarding against is not "the campaign found nothing".
# It is "the campaign never started" -- a harness that cannot speak the
# protocol, or an engine that aborted -- which without this check looks
# exactly like a clean run.
library(zufuzz)

harness <- system.file("smoke", "harness.R", package = "zufuzz")
stopifnot(nzchar(harness))

corpus <- tempfile("smoke-corpus-")
dir.create(corpus, recursive = TRUE)
# Seeded one byte from the guarded branch, so the run is quick and its
# outcome does not depend on the mutator getting lucky.
writeBin(charToRaw("za"), file.path(corpus, "seed"))

cat("engines available:\n")
print(engines())

result <- fuzz_file(
  harness,
  corpus = corpus,
  engine = "afl",
  time_limit = 60,
  seed = 1,
  artifact_dir = ".zufuzz/artifacts",
  quiet = FALSE
)

if (identical(result$stop_reason, "infrastructure")) {
  cat("\n==smoke== the campaign never started:\n", result$stderr, "\n")
  quit(save = "no", status = 1L)
}
if (!identical(result$stop_reason, "finding")) {
  cat("\n==smoke== expected a finding, got", result$stop_reason, "\n")
  quit(save = "no", status = 1L)
}

# And the finding has to survive a fresh, uninstrumented process.
confirmation <- replay(harness, result$finding$artifact)
cat("\nreplay:", confirmation$outcome,
    if (isTRUE(confirmation$confirmed)) "(confirmed)" else "(NOT confirmed)", "\n")
if (!isTRUE(confirmation$confirmed)) {
  quit(save = "no", status = 1L)
}

cat("\n==smoke== ok\n")
