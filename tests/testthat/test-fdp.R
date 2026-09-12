# Stage 8: the byte-to-value mapping.
#
# The expectations below are computed by hand from the documented algorithm,
# not captured from a run. A test that records what the code currently does
# would pass forever and tell you nothing about whether a corpus still means
# what it meant.
#
# The algorithm, for the cases asserted here:
#   bytes    taken from the front, in order
#   integers taken from the back; each byte shifts the accumulator left 8 and
#            ORs in, so the last byte of the input is the most significant
#   in_range width = max - min + 1; enough bytes to cover width - 1; then
#            min + (raw %% width)

test_that("bytes come from the front, in order", {
  fdp <- fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))
  expect_identical(fdp$consume_bytes(2), as.raw(c(1, 2)))
  expect_identical(fdp$remaining_bytes(), 2)
  expect_identical(fdp$consume_bytes(1), as.raw(3))
  expect_identical(fdp$consume_remaining_bytes(), as.raw(4))
  expect_identical(fdp$remaining_bytes(), 0)
})

test_that("integers come from the back", {
  # One byte needed for 0..255, so the *last* byte is taken: 4.
  expect_identical(
    fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))$consume_int_in_range(0, 255),
    4L
  )
  # Two bytes for 0..65535: last byte then the one before, so (4 << 8) | 3.
  expect_identical(
    fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))$consume_int_in_range(0, 65535),
    1027L
  )
  # min is an offset, not a mask.
  expect_identical(
    fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))$consume_int_in_range(100, 355),
    104L
  )
})

test_that("front and back never overlap", {
  fdp <- fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))
  expect_identical(fdp$consume_int_in_range(0, 255), 4L) # takes the back byte
  expect_identical(fdp$consume_bytes(3), as.raw(c(1, 2, 3))) # front sees the rest
  expect_identical(fdp$remaining_bytes(), 0)
  # Exhausted: no byte is handed out twice.
  expect_identical(fdp$consume_bytes(1), raw(0))
})

test_that("a range of one value needs no bytes at all", {
  fdp <- fuzzed_data_provider(as.raw(c(7, 8)))
  expect_identical(fdp$consume_int_in_range(5, 5), 5L)
  expect_identical(fdp$remaining_bytes(), 2)
})

test_that("a reversed range is accepted rather than refused", {
  # Fuzzed code computes its own bounds; refusing here would turn a target's
  # quirk into a harness error.
  fdp <- fuzzed_data_provider(as.raw(c(1, 2, 3, 4)))
  expect_identical(fdp$consume_int_in_range(255, 0), 4L)
})

test_that("nothing errors and everything is defined when input is empty", {
  fdp <- fuzzed_data_provider(raw(0))
  expect_identical(fdp$remaining_bytes(), 0)
  expect_identical(fdp$consume_bytes(10), raw(0))
  expect_identical(fdp$consume_remaining_bytes(), raw(0))
  expect_identical(fdp$consume_string(), "")
  expect_identical(fdp$consume_int(), 0L)
  expect_identical(fdp$consume_int_in_range(1, 100), 1L)
  expect_identical(fdp$consume_bool(), FALSE)
  expect_identical(fdp$consume_probability(), 0)
  expect_true(is.numeric(fdp$consume_double()))
  expect_identical(fdp$consume_int_list(5), rep(0L, 5L))
  expect_null(fdp$pick_value(list()))
})

test_that("one byte is enough for every method", {
  for (method in c("consume_int", "consume_bool", "consume_probability", "consume_double")) {
    fdp <- fuzzed_data_provider(as.raw(42))
    expect_silent(fdp[[method]]())
  }
  fdp <- fuzzed_data_provider(as.raw(42))
  expect_identical(fdp$consume_bytes(1), as.raw(42))
})

test_that("a partly exhausted provider keeps returning values", {
  fdp <- fuzzed_data_provider(as.raw(c(1, 2)))
  fdp$consume_bytes(2)
  expect_identical(fdp$remaining_bytes(), 0)
  # Everything past the end is a value, not a failure.
  expect_identical(fdp$consume_int(), 0L)
  expect_identical(fdp$consume_bool(), FALSE)
  expect_identical(fdp$consume_string(), "")
})

# The provider is handed adversarial bytes by definition. Erroring would
# report a defect in the harness as a defect in the target.
test_that("consume_string never errors, on any byte sequence", {
  set.seed(1)
  for (i in seq_len(300)) {
    bytes <- as.raw(sample.int(256, sample.int(64, 1), replace = TRUE) - 1L)
    for (enc in c("utf8", "ascii", "bytes")) {
      value <- fuzzed_data_provider(bytes)$consume_string(encoding = enc)
      expect_type(value, "character")
      expect_length(value, 1L)
      expect_false(is.na(value))
    }
  }
})

test_that("strings never contain an embedded NUL", {
  # R strings cannot hold one at all; rawToChar() errors on it, and that error
  # would belong to the harness rather than the target.
  bytes <- as.raw(c(65, 0, 66, 0, 67))
  expect_identical(fuzzed_data_provider(bytes)$consume_string(encoding = "bytes"), "ABC")
  expect_identical(fuzzed_data_provider(bytes)$consume_string(encoding = "ascii"), "ABC")
})

test_that("ascii encoding masks every byte to seven bits", {
  bytes <- as.raw(c(0xC1, 0xE2)) # 193, 226 -> 65, 98
  expect_identical(fuzzed_data_provider(bytes)$consume_string(encoding = "ascii"), "Ab")
})

test_that("utf8 output is valid UTF-8 whatever went in", {
  set.seed(2)
  for (i in seq_len(200)) {
    bytes <- as.raw(sample.int(256, sample.int(32, 1), replace = TRUE) - 1L)
    value <- fuzzed_data_provider(bytes)$consume_string(encoding = "utf8")
    expect_true(isTRUE(validUTF8(value)) || !nzchar(value))
  }
})

# NA_integer_ is INT_MIN. A provider that returned it would make every harness
# handle a case the fuzzer invented rather than the target's own domain.
test_that("integers are never NA", {
  set.seed(3)
  for (i in seq_len(400)) {
    bytes <- as.raw(sample.int(256, sample.int(16, 1), replace = TRUE) - 1L)
    fdp <- fuzzed_data_provider(bytes)
    expect_false(is.na(fdp$consume_int()))
    expect_false(is.na(fdp$consume_int_in_range(-1000, 1000)))
    expect_false(anyNA(fdp$consume_int_list(4)))
  }
})

test_that("logicals are never NA", {
  set.seed(4)
  for (i in seq_len(200)) {
    bytes <- as.raw(sample.int(256, sample.int(8, 1), replace = TRUE) - 1L)
    expect_false(is.na(fuzzed_data_provider(bytes)$consume_bool()))
  }
})

test_that("probabilities stay in the unit interval", {
  set.seed(5)
  for (i in seq_len(200)) {
    bytes <- as.raw(sample.int(256, 16, replace = TRUE) - 1L)
    p <- fuzzed_data_provider(bytes)$consume_probability()
    expect_gte(p, 0)
    expect_lt(p, 1)
  }
})

test_that("numbers in range stay in range", {
  set.seed(6)
  for (i in seq_len(200)) {
    bytes <- as.raw(sample.int(256, 16, replace = TRUE) - 1L)
    v <- fuzzed_data_provider(bytes)$consume_number_in_range(-5, 5)
    expect_gte(v, -5)
    expect_lte(v, 5)
    expect_false(is.na(v))
  }
})

test_that("consume_double reaches the special values, but only when allowed", {
  seen <- character(0)
  for (b in 0:255) {
    v <- fuzzed_data_provider(as.raw(c(rep(0, 8), b)))$consume_double(allow_special = TRUE)
    if (is.nan(v)) seen <- c(seen, "NaN")
    if (identical(v, Inf)) seen <- c(seen, "Inf")
    if (identical(v, -Inf)) seen <- c(seen, "-Inf")
    if (!is.nan(v) && is.na(v)) seen <- c(seen, "NA")
  }
  # These take different paths through most numeric code, which is where real
  # defects live, so they have to be reachable.
  expect_true(all(c("NaN", "Inf", "-Inf", "NA") %in% seen))

  set.seed(7)
  for (i in seq_len(200)) {
    bytes <- as.raw(sample.int(256, 16, replace = TRUE) - 1L)
    v <- fuzzed_data_provider(bytes)$consume_double(allow_special = FALSE)
    expect_true(is.finite(v))
  }
})

test_that("consumed lengths never exceed what was there", {
  set.seed(8)
  for (i in seq_len(200)) {
    n <- sample.int(32, 1)
    bytes <- as.raw(sample.int(256, n, replace = TRUE) - 1L)
    fdp <- fuzzed_data_provider(bytes)
    taken <- length(fdp$consume_bytes(sample.int(64, 1)))
    expect_lte(taken, n)
    expect_identical(fdp$consumed_bytes() + fdp$remaining_bytes(), as.double(n))
  }
})

test_that("an absurd length does not allocate absurdly", {
  fdp <- fuzzed_data_provider(as.raw(1:8))
  # Four fuzzed bytes can ask for four billion elements; clamping is what
  # stops a harness dying of a length the target never chose.
  expect_lte(length(fdp$consume_int_list(1e12)), 1e6)
  expect_identical(length(fdp$consume_int_list(-1)), 0L)
  expect_identical(length(fdp$consume_int_list(NA)), 0L)
})

test_that("pick_value chooses from the vector it was given", {
  set.seed(9)
  choices <- c("a", "b", "c", "d")
  for (i in seq_len(50)) {
    bytes <- as.raw(sample.int(256, 4, replace = TRUE) - 1L)
    expect_true(fuzzed_data_provider(bytes)$pick_value(choices) %in% choices)
  }
})

test_that("the same bytes give the same values, every time", {
  bytes <- as.raw(c(9, 8, 7, 6, 5, 4, 3, 2, 1))
  read_all <- function() {
    fdp <- fuzzed_data_provider(bytes)
    list(
      fdp$consume_bytes(2), fdp$consume_int_in_range(1, 1000),
      fdp$consume_double(), fdp$consume_string(2), fdp$consume_bool()
    )
  }
  expect_identical(read_all(), read_all())
})

test_that("the provider copies its input rather than borrowing it", {
  bytes <- as.raw(c(1, 2, 3, 4))
  fdp <- fuzzed_data_provider(bytes)
  bytes[[1L]] <- as.raw(99)
  # A provider that changed meaning underneath a harness would break
  # reproduction in a way nobody could debug.
  expect_identical(fdp$consume_bytes(1), as.raw(1))
})

test_that("reset rewinds to the start", {
  fdp <- fuzzed_data_provider(as.raw(1:4))
  first <- fdp$consume_bytes(2)
  fdp$reset()
  expect_identical(fdp$remaining_bytes(), 4)
  expect_identical(fdp$consume_bytes(2), first)
})

test_that("a provider prints its state", {
  expect_output(print(fuzzed_data_provider(as.raw(1:4))), "data provider")
})
