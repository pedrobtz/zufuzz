# Fixture: fails only the second time it sees anything in a process. A replay
# runs one input in a fresh process, so this must come back NOT confirmed --
# the finding depended on history, not on the bytes.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

seen <- 0L
target <- function(data) {
  seen <<- seen + 1L
  if (seen >= 2L) stop("zufuzz fixture: only fails with history")
  invisible(NULL)
}

fuzz(target, engine = "none", quiet = TRUE)
