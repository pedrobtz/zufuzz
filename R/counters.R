# The coverage counter region, and where its increments land.
#
# All internal for now: Stage 3 plants probes that call into it, Stage 5's
# engines() reports on it, and Stage 6 attaches the AFL sink. Nothing here is
# exported until the stage that documents it.

# Kept in step with the ZUFUZZ_SINK_* macros in src/zufuzz.h.
sink_modes <- c(none = 0L, afl = 1L, libfuzzer = 2L)

#' Allocate the counter region
#'
#' One `uint8_t` per instrumentation site. Sized from the frozen plan, and
#' refused once an engine has attached: a site id handed out before a campaign
#' started must still mean the same counter afterwards.
#'
#' @param n Number of sites.
#' @return The number of counters allocated, invisibly.
#' @noRd
counter_alloc <- function(n) {
  invisible(.Call(C_zufuzz_region_alloc, as.double(n)))
}

#' @noRd
counter_size <- function() {
  .Call(C_zufuzz_region_size)
}

#' Read the region back
#'
#' A copy, so R never holds a pointer into the live region. Integer rather
#' than raw because a hit count is a number, and because the counters
#' saturate at 255 in C and a reader should see that plainly.
#'
#' @noRd
counter_hits <- function() {
  as.integer(.Call(C_zufuzz_region_read))
}

#' @noRd
counter_reset <- function() {
  invisible(.Call(C_zufuzz_region_reset))
}

#' Point the probes at an engine's coverage map
#'
#' Freezes the region. `map` is required for `"afl"` (the supervisor's
#' bitmap, or a raw vector in tests) and ignored otherwise; it must be a
#' power of two in size so the edge wrap is a mask rather than a division.
#'
#' @noRd
counter_attach <- function(mode = c("none", "afl", "libfuzzer"), map = NULL) {
  mode <- match.arg(mode)
  invisible(.Call(C_zufuzz_attach_sink, sink_modes[[mode]], map))
}

#' @noRd
counter_sink <- function() {
  names(sink_modes)[match(.Call(C_zufuzz_sink_mode), sink_modes)]
}

#' @noRd
counter_frozen <- function() {
  .Call(C_zufuzz_is_frozen)
}

#' Release the freeze
#'
#' For tests and development only, so a session can exercise the freeze rule
#' more than once. An engine never thaws a region.
#'
#' @noRd
counter_thaw <- function() {
  invisible(.Call(C_zufuzz_thaw))
}

#' Record a hit on one site
#'
#' Stage 3 plants `.Call()` to the native symbol directly rather than calling
#' this, so that nothing user-shadowable is looked up on the hot path. This
#' wrapper exists for tests and for reasoning about the C.
#'
#' @noRd
counter_probe <- function(id) {
  invisible(.Call(C_zufuzz_probe, as.integer(id)))
}
