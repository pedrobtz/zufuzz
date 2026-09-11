# Fixture: fails before any input runs. The harness itself is broken, which is
# infrastructure, not a finding -- reporting it as a finding would send
# someone hunting a defect in a package that was never loaded.
lib <- Sys.getenv("ZUFUZZ_TEST_LIB")
if (nzchar(lib)) .libPaths(c(lib, .libPaths()))
library(zufuzz)
library(definitelyNotARealPackage.zufuzz)
fuzz(function(data) NULL, engine = "none", quiet = TRUE)
