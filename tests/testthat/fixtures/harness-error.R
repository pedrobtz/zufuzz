# Fixture: errors on any input beginning with "zf". Deterministic, so a replay
# of the same bytes must always produce the same fingerprint.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

target <- function(data) {
  if (length(data) >= 2L && identical(as.integer(data[1:2]), c(122L, 102L))) {
    stop("zufuzz fixture: magic prefix reached")
  }
  invisible(NULL)
}

fuzz(target, engine = "none", quiet = TRUE)
