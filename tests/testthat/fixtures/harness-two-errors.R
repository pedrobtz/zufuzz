# Fixture: two distinct errors, chosen by the first byte. Used to show the
# ZUFUZZ_EXPECT_FINGERPRINT gate records only the one it was asked for.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

target <- function(data) {
  if (!length(data)) return(invisible(NULL))
  if (data[[1L]] == as.raw(0x01)) stop("zufuzz fixture: first kind of error")
  if (data[[1L]] == as.raw(0x02)) stop("zufuzz fixture: second kind of error")
  invisible(NULL)
}

fuzz(target, engine = "none", quiet = TRUE)
