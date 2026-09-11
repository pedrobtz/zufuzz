# Fixture: a campaign that cannot find anything. `engine = "auto"` so it
# really becomes a worker under a supervisor -- a harness that hardcodes
# engine = "none" runs its inputs once and exits without ever speaking the
# protocol, which AFL reports as a broken target.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)
fuzz(function(data) invisible(length(data)), engine = "auto", quiet = TRUE)
