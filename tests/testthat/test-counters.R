# Stage 1: the counter region and its three sink modes.
#
# Every test thaws first and leaves the region in `none` mode, because the
# region is process-global by design -- libFuzzer needs a stable address for
# the life of the process -- so tests would otherwise leak state into each
# other.

reset_counters <- function(n = 16) {
  counter_thaw()
  counter_alloc(n)
  counter_reset()
}

withr_teardown <- function() {
  counter_thaw()
  counter_alloc(0)
}

test_that("the region allocates, reads back zeroed, and resizes", {
  reset_counters(16)
  on.exit(withr_teardown(), add = TRUE)

  expect_identical(counter_size(), 16)
  expect_identical(counter_hits(), integer(16))

  counter_alloc(4)
  expect_identical(counter_size(), 4)
  expect_identical(counter_hits(), integer(4))

  counter_alloc(0)
  expect_identical(counter_size(), 0)
  expect_identical(counter_hits(), integer(0))
})

test_that("a probe bumps its own counter and nothing else", {
  reset_counters(8)
  on.exit(withr_teardown(), add = TRUE)

  counter_probe(3)
  expect_identical(counter_hits(), c(0L, 0L, 0L, 1L, 0L, 0L, 0L, 0L))

  counter_probe(3)
  counter_probe(0)
  expect_identical(counter_hits(), c(1L, 0L, 0L, 2L, 0L, 0L, 0L, 0L))

  counter_reset()
  expect_identical(counter_hits(), integer(8))
})

# The roadmap's completion criterion, literally: a fixture that bumps counter
# k on input byte k reads back the expected region.
test_that("counter k is bumped for input byte k", {
  reset_counters(256)
  on.exit(withr_teardown(), add = TRUE)

  input <- as.raw(c(0x00, 0x07, 0x07, 0xff))
  for (byte in input) counter_probe(as.integer(byte))

  hits <- counter_hits()
  expect_identical(hits[[1L]], 1L) # 0x00
  expect_identical(hits[[8L]], 2L) # 0x07, twice
  expect_identical(hits[[256L]], 1L) # 0xff
  expect_identical(sum(hits), 4L)
})

test_that("hit counts wrap at 256, as sancov and AFL both do", {
  reset_counters(2)
  on.exit(withr_teardown(), add = TRUE)

  for (i in seq_len(255)) counter_probe(0)
  expect_identical(counter_hits()[[1L]], 255L)

  # Deliberately NOT saturating. An inline 8-bit counter is `*p += 1` in
  # sancov and `map[loc]++` in AFL; both wrap, and both bucket the result, so
  # a site hit exactly 256 times reads as never hit. Saturating here would be
  # more intuitive but would make zufuzz's counters mean something different
  # from the native ones libFuzzer sees in the same process.
  counter_probe(0)
  expect_identical(counter_hits()[[1L]], 0L)

  counter_probe(0)
  expect_identical(counter_hits()[[1L]], 1L)
})

test_that("the AFL sink writes the expected edges for a known sequence", {
  reset_counters(16)
  on.exit(withr_teardown(), add = TRUE)

  map <- raw(64L)
  counter_attach("afl", map)
  expect_identical(counter_sink(), "afl")

  # prev starts at 0 and becomes id >> 1 after each hit:
  #   probe(3): 3 ^ 0 ==  3, prev := 1
  #   probe(5): 5 ^ 1 ==  4, prev := 2
  #   probe(9): 9 ^ 2 == 11, prev := 4
  counter_probe(3)
  counter_probe(5)
  counter_probe(9)

  hit <- which(as.integer(map) > 0L)
  expect_identical(hit, c(4L, 5L, 12L)) # 1-based
  expect_identical(as.integer(map)[hit], c(1L, 1L, 1L))

  # The region itself is untouched: in afl mode the increments go to the
  # supervisor's map, not to the local counters.
  expect_identical(sum(counter_hits()), 0L)
})

test_that("the AFL sink distinguishes the same sites in a different order", {
  on.exit(withr_teardown(), add = TRUE)

  edges_for <- function(ids) {
    counter_thaw()
    counter_alloc(16)
    map <- raw(64L)
    counter_attach("afl", map)
    for (id in ids) counter_probe(id)
    which(as.integer(map) > 0L)
  }

  # Edge coverage, not block coverage: the same two sites reached in the
  # other order must look different, or the sink is not earning its keep.
  expect_false(identical(edges_for(c(3, 5)), edges_for(c(5, 3))))
})

test_that("the AFL map must be a power of two", {
  reset_counters(8)
  on.exit(withr_teardown(), add = TRUE)

  expect_error(counter_attach("afl", raw(63L)), "power of two")
  expect_error(counter_attach("afl", NULL), "raw vector or a map pointer")
})

test_that("libfuzzer and none sinks both use the local region", {
  reset_counters(8)
  on.exit(withr_teardown(), add = TRUE)

  counter_attach("libfuzzer")
  expect_identical(counter_sink(), "libfuzzer")
  counter_probe(2)
  expect_identical(counter_hits()[[3L]], 1L)

  counter_thaw()
  expect_identical(counter_sink(), "none")
  counter_probe(2)
  expect_identical(counter_hits()[[3L]], 2L)
})

test_that("attaching an engine freezes the region", {
  reset_counters(8)
  on.exit(withr_teardown(), add = TRUE)

  expect_false(counter_frozen())
  counter_alloc(12) # still allowed

  counter_attach("libfuzzer")
  expect_true(counter_frozen())

  # A site id handed out before the campaign started must still mean the same
  # counter afterwards, so resizing is refused rather than silently honoured.
  expect_error(counter_alloc(4), "frozen")
  expect_identical(counter_size(), 12)
})

test_that("the region is reachable through the companion's C interface", {
  reset_counters(32)
  on.exit(withr_teardown(), add = TRUE)

  # Resolved with R_GetCCallable("zufuzz", "zufuzz_counter_region"), which is
  # exactly how zufuzz.libfuzzer will reach it before handing (start, end) to
  # __sanitizer_cov_8bit_counters_init on its own side of the boundary.
  expect_identical(.Call(C_zufuzz_region_via_ccallable), 32)

  counter_alloc(8)
  expect_identical(.Call(C_zufuzz_region_via_ccallable), 8)

  counter_alloc(0)
  expect_identical(.Call(C_zufuzz_region_via_ccallable), 0)
})

test_that("probes are harmless before anything is allocated", {
  counter_thaw()
  counter_alloc(0)
  on.exit(withr_teardown(), add = TRUE)

  # Stage 3 can plant probes in code that runs before a region exists; that
  # must be inert rather than a crash.
  expect_silent(counter_probe(0))
  expect_silent(counter_probe(1000))
  expect_identical(counter_hits(), integer(0))
})
