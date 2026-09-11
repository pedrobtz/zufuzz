# Fixture: the *same* marker raises a different error once the input gets
# short. A reducer that only asks "does it still fail" walks straight from one
# bug into the other and reports a smaller reproducer for a bug that was never
# being minimized. This is the case the fingerprint gate exists for.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)

target <- function(data) {
  text <- rawToChar(data[data != as.raw(0)])
  Encoding(text) <- "UTF-8"
  if (!isTRUE(validUTF8(text))) text <- ""
  if (!grepl("zf", text, fixed = TRUE)) {
    return(invisible(NULL))
  }
  if (length(data) >= 8L) {
    stop("zufuzz fixture: the long-input defect")
  }
  stop("zufuzz fixture: a completely different defect")
}

fuzz(target, engine = "none", quiet = TRUE)
