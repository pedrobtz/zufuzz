# Fixture: runs far longer than any test budget, so the launcher's time_limit
# has to stop it. Reaching a wall-clock budget is `budget`, not a finding.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)
Sys.sleep(120)
