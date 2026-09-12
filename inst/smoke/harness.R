# The toy harness the smoke workflow fuzzes. Deliberately easy: the point is
# that the machinery still works end to end, not that the search is clever.
library(zufuzz)

decode <- function(data) {
  if (length(data) >= 1L && data[[1L]] == as.raw(0x7a)) {
    if (length(data) >= 2L && data[[2L]] == as.raw(0x66)) {
      stop("zufuzz smoke: reached the guarded branch")
    }
    return("first byte")
  }
  "neither"
}
instrument("decode")

fuzz(function(data) decode(data), engine = "auto", quiet = TRUE)
