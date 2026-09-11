# Fixture: a campaign that cannot find anything.
#
# Two things this has to get right, both learned the hard way:
#   engine = "auto"  so it really becomes a worker; a harness that hardcodes
#                    run-once exits without speaking the protocol.
#   instrument()     AFL aborts with "no instrumentation detected" when the
#                    coverage bitmap is still all-zero after its dry run, so
#                    an uninstrumented harness never starts a campaign at all.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

# Branches, so the map is non-empty, but no path raises an error.
shape <- function(data) {
  if (length(data) > 4L) {
    "long"
  } else if (length(data) > 0L) {
    "short"
  } else {
    "empty"
  }
}
instrument("shape")

fuzz(function(data) invisible(shape(data)), engine = "auto", quiet = TRUE)
