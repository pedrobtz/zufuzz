# Fixture: fails whenever the marker appears anywhere in the input, whatever
# surrounds it. A correct reducer shrinks any failing input down to the marker.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

target <- function(data) {
  text <- rawToChar(data[data != as.raw(0)])
  Encoding(text) <- "UTF-8"
  if (!isTRUE(validUTF8(text))) text <- ""
  if (grepl("zf", text, fixed = TRUE)) {
    stop("zufuzz fixture: marker present")
  }
  invisible(NULL)
}

fuzz(target, engine = "none", quiet = TRUE)
