# Fixture harness for a real campaign. `engine = "auto"` is the point: the
# same file runs as an AFL worker when a supervisor is attached, and as
# run-once when one is not, with nothing changed.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

# Instrumented so the campaign has something to steer by: a nested prefix an
# unguided search would take a long time to reach.
classify <- function(data) {
  if (length(data) >= 1L && data[[1L]] == as.raw(0x7a)) {
    if (length(data) >= 2L && data[[2L]] == as.raw(0x66)) {
      stop("zufuzz fixture: reached the nested prefix")
    }
    return("first byte only")
  }
  "neither"
}
instrument("classify")

fuzz(function(data) classify(data), engine = "auto", quiet = TRUE)
