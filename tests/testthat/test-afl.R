# Stage 6: the AFL worker protocol.
#
# Split deliberately in two. The parts that need no supervisor -- command-line
# construction, flag mapping, artifact import, engine resolution -- are tested
# everywhere. The protocol itself needs something that speaks it, so those
# tests run only where afl-fuzz is installed, which is the one CI job that
# installs it. A protocol cannot be verified against a mock of itself.

skip_without_afl <- function() {
  skip_if_not(engine_available("afl"), "afl-fuzz is not installed")
}

corpus_with <- function(...) {
  dir <- tempfile("zufuzz-corpus-")
  dir.create(dir, recursive = TRUE)
  items <- list(...)
  for (i in seq_along(items)) {
    writeBin(items[[i]], file.path(dir, sprintf("in-%02d", i)))
  }
  dir
}

# -- no supervisor needed ------------------------------------------------

test_that("AFL flags map to afl-fuzz options, and unknown ones are refused", {
  expect_identical(afl_flag_arguments(list(dict = "d.txt")), c("-x", "d.txt"))
  expect_identical(afl_flag_arguments(list(timeout = 100)), c("-t", "100"))
  expect_identical(
    afl_flag_arguments(list(dict = "d.txt", memory = "none")),
    c("-x", "d.txt", "-m", "none")
  )
  expect_identical(afl_flag_arguments(list()), character(0))

  # libFuzzer's spelling must not silently reach afl-fuzz, which has no such
  # option and would fail with its own vocabulary.
  expect_error(afl_flag_arguments(list(max_len = 4096)), "no option for")
  expect_error(afl_flag_arguments(list("x")), "must be named")
})

test_that("the command line puts budgets before the target", {
  argv <- afl_command(
    "afl-fuzz", "corpus", "out", "h.R", character(), list(),
    time_limit = 30, runs = Inf
  )
  expect_identical(argv[1:4], c("-i", "corpus", "-o", "out"))
  expect_true("-V" %in% argv)
  expect_identical(argv[[which(argv == "-V") + 1L]], "30")
  # Everything after `--` is the target, and it has to come last.
  sep <- which(argv == "--")
  expect_length(sep, 1L)
  expect_true(all(which(argv %in% c("-i", "-o", "-V", "-E")) < sep))
  expect_identical(utils::tail(argv, 1L), "h.R")

  # -E is an execution budget; both budgets make afl-fuzz exit by itself,
  # which is what lets CI run a campaign at all.
  runs_argv <- afl_command(
    "afl-fuzz", "corpus", "out", "h.R", character(), list(),
    time_limit = Inf, runs = 500
  )
  expect_true("-E" %in% runs_argv)
  expect_false("-V" %in% runs_argv)
})

test_that("a campaign without a corpus is infrastructure, not a crash", {
  result <- run_afl_campaign(
    harness = "h.R", corpus = NULL, args = character(), dots = list(),
    time_limit = 5, runs = Inf, artifact_dir = tempfile(),
    env = character(), quiet = TRUE
  )
  # afl-fuzz refuses to start without seeds, and its own message is about
  # directories rather than about what the caller forgot.
  expect_identical(result$stop_reason, "infrastructure")
  expect_match(result$stderr, "corpus|not found")
})

test_that("AFL findings are imported under zufuzz names, leaving AFL's alone", {
  # AFL names its findings with colons (`id:000000,sig:06`), which Windows
  # forbids in a filename, so the fixture cannot even be created there. AFL
  # does not run on Windows either, so this path is unreachable rather than
  # untested.
  skip_on_os("windows")

  out_dir <- tempfile("afl-out-")
  artifacts <- tempfile("zufuzz-art-")
  dir.create(file.path(out_dir, "default", "crashes"), recursive = TRUE)
  dir.create(file.path(out_dir, "default", "hangs"), recursive = TRUE)
  dir.create(artifacts, recursive = TRUE)

  crash_bytes <- charToRaw("zf-crash")
  hang_bytes <- charToRaw("zf-hang")
  writeBin(crash_bytes, file.path(out_dir, "default", "crashes", "id:000000,sig:06"))
  writeBin(hang_bytes, file.path(out_dir, "default", "hangs", "id:000000,src:000001"))
  # AFL writes a README into crashes/; it is not a finding.
  writeLines("not an input", file.path(out_dir, "default", "crashes", "README.txt"))

  import_afl_findings(out_dir, artifacts)

  expect_true(file.exists(file.path(artifacts, artifact_name(crash_bytes, "crash"))))
  expect_true(file.exists(file.path(artifacts, artifact_name(hang_bytes, "timeout"))))
  expect_length(list.files(artifacts, pattern = "^crash-[0-9a-f]+$"), 1L)
  expect_length(list.files(artifacts, pattern = "^timeout-[0-9a-f]+$"), 1L)

  # Every artifact has a sidecar, even one the child could not describe, so
  # downstream tooling never has to special-case.
  sidecar <- read_sidecar(file.path(artifacts, artifact_name(hang_bytes, "timeout")))
  expect_identical(sidecar$kind, "timeout")
  expect_identical(sidecar$engine, "afl")

  # AFL's own directory is untouched, so afl-cmin, afl-tmin and afl-whatsup
  # keep working on it.
  expect_true(file.exists(file.path(out_dir, "default", "crashes", "id:000000,sig:06")))

  # Importing twice must not duplicate.
  import_afl_findings(out_dir, artifacts)
  expect_length(list.files(artifacts, pattern = "^crash-[0-9a-f]+$"), 1L)
})

test_that("parallel-instance output directories are imported too", {
  # AFL names its findings with colons (`id:000000,sig:06`), which Windows
  # forbids in a filename, so the fixture cannot even be created there. AFL
  # does not run on Windows either, so this path is unreachable rather than
  # untested.
  skip_on_os("windows")

  out_dir <- tempfile("afl-out-")
  artifacts <- tempfile("zufuzz-art-")
  # -M/-S runs put findings under <out>/<instance>/ rather than <out>/default/.
  dir.create(file.path(out_dir, "secondary01", "crashes"), recursive = TRUE)
  dir.create(artifacts, recursive = TRUE)
  writeBin(charToRaw("from-a-secondary"), file.path(out_dir, "secondary01", "crashes", "id:000001,sig:06"))

  import_afl_findings(out_dir, artifacts)
  expect_length(list.files(artifacts, pattern = "^crash-[0-9a-f]+$"), 1L)
})

test_that("the worker reads its input from the file AFL substituted", {
  path <- tempfile("afl-input-")
  writeBin(charToRaw("from the file"), path)
  # afl_read_input() prefers a path on the command line because AFL rewrites
  # the same file each round; stdin is the fallback.
  expect_identical(read_input(path), charToRaw("from the file"))
})

test_that("attaching fails cleanly when there is no supervisor", {
  skip_if_not(isTRUE(.Call(C_zufuzz_afl_supported)), "no System V shared memory")
  # A bogus id must be a clean FALSE, not a crash: a harness run by hand
  # should fall back rather than die.
  expect_false(isTRUE(.Call(C_zufuzz_afl_attach, "not-a-real-shm-id", 65536)))
  expect_false(isTRUE(.Call(C_zufuzz_afl_attach, "", 65536)))
})

test_that("the fork server declines when nobody is listening", {
  skip_if_not(isTRUE(.Call(C_zufuzz_afl_supported)), "no System V shared memory")
  skip_if(nzchar(Sys.getenv("__AFL_SHM_ID")), "a supervisor is attached")
  # Descriptor 199 is not open, so the hello write fails and this returns
  # FALSE rather than blocking forever on a pipe nobody holds. That is what
  # lets `Rscript harness.R` with engine = "auto" fall back to run-once.
  expect_false(isTRUE(.Call(C_zufuzz_afl_forkserver)))
})

test_that("the same harness runs without a supervisor", {
  skip_if(
    is.na(installed_zufuzz_lib()),
    "zufuzz is not installed; the harness runs in a child"
  )
  # engine = "auto" with nothing attached must be run-once. The same file
  # under afl-fuzz is a worker; that is the whole point of the seam.
  result <- fuzz_file(
    test_path("fixtures", "harness-afl.R"),
    corpus = corpus_with(charToRaw("zf"), charToRaw("aa")),
    quiet = TRUE
  )
  expect_identical(result$engine, "none")
  expect_identical(result$stop_reason, "finding")
})

# -- needs a real supervisor ---------------------------------------------

test_that("a campaign finds the planted error and imports it", {
  skip_without_afl()
  skip_if(is.na(installed_zufuzz_lib()), "zufuzz is not installed")

  result <- fuzz_file(
    test_path("fixtures", "harness-afl.R"),
    corpus = corpus_with(charToRaw("aa")),
    engine = "afl",
    time_limit = 45,
    quiet = TRUE
  )

  expect_identical(result$engine, "afl")
  # Guided search has to get from "aa" to the nested "zf" prefix. Instrumented
  # coverage is what makes that reachable in a short budget; unguided it is
  # one in 65536 per byte pair.
  expect_identical(result$stop_reason, "finding")
  expect_true(length(result$findings) >= 1L)
  expect_true(file.exists(result$finding$artifact))
})

test_that("a campaign over a target that cannot fail exhausts its budget", {
  skip_without_afl()
  skip_if(is.na(installed_zufuzz_lib()), "zufuzz is not installed")

  result <- fuzz_file(
    test_path("fixtures", "harness-ok.R"),
    corpus = corpus_with(charToRaw("aa")),
    engine = "afl",
    time_limit = 20,
    quiet = TRUE
  )
  expect_identical(result$stop_reason, "budget")
  expect_length(result$findings, 0L)
})
