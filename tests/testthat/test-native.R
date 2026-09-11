# Stage 0: the native layer is registered and the platform guard reports
# honestly. Both are preconditions for every later stage, and the second is
# what makes Windows a supported installation platform rather than a broken
# one -- the package loads, and says plainly that it cannot attach to a
# fuzzing supervisor.

test_that("native routines are registered", {
  expect_true("zufuzz" %in% names(getLoadedDLLs()))
  expect_s3_class(zufuzz:::C_zufuzz_afl_supported, "NativeSymbolInfo")
})

test_that("AFL support is reported, and matches the platform", {
  supported <- .Call(zufuzz:::C_zufuzz_afl_supported)

  expect_type(supported, "logical")
  expect_length(supported, 1L)
  expect_false(is.na(supported))

  # System V shared memory is the requirement; Rtools has none.
  expect_identical(supported, .Platform$OS.type == "unix")
})
