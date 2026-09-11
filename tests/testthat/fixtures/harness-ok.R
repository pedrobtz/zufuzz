# Fixture: never errors, whatever it is given.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)
fuzz(function(data) invisible(length(data)), engine = "none", quiet = TRUE)
