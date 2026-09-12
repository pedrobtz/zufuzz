# The R face of the data provider.
#
# Thin on purpose. Every decision about *which* bytes become *which* value
# lives in src/fdp.c, because `draw()` is the second front door onto the same
# mapping and two implementations would drift -- silently, since the symptom
# is a corpus that quietly stops meaning what it meant.
#
# The consumption algorithm is part of the documented API, not an
# implementation detail: it determines whether a corpus recorded today still
# means the same thing after an upgrade.

#' Turn fuzzed bytes into typed values
#'
#' A harness receives one raw vector. Most targets want more than one value
#' out of it, and splitting bytes by hand is where harnesses go wrong. This
#' mirrors LLVM's `FuzzedDataProvider`, so corpora and habits carry over from
#' C++ and from Atheris.
#'
#' Two guarantees hold for every method:
#'
#' * **Nothing errors, on any byte sequence.** Fuzzed input is adversarial by
#'   definition; a provider that threw would report a defect in the harness as
#'   a defect in the target.
#' * **Exhaustion is a value, not a failure.** Past the end of the input,
#'   methods return zero-length or zero-ish results and the cursor stops.
#'
#' Bytes are taken from the front and integers from the back, as LLVM does, so
#' the two never overlap.
#'
#' @param data A raw vector.
#' @return A `zufuzz_fdp` object; call its methods with `$`.
#' @export
#' @examples
#' fdp <- fuzzed_data_provider(as.raw(c(1, 2, 3, 4, 5, 6, 7, 8)))
#' fdp$consume_bytes(2)
#' fdp$consume_int_in_range(1, 10)
#' fdp$remaining_bytes()
fuzzed_data_provider <- function(data) {
  if (!is.raw(data)) {
    data <- as.raw(data)
  }
  ptr <- .Call(C_zufuzz_fdp_create, data)

  self <- list(
    remaining_bytes = function() {
      .Call(C_zufuzz_fdp_remaining, ptr)
    },
    consumed_bytes = function() {
      .Call(C_zufuzz_fdp_consumed, ptr)
    },
    consume_bytes = function(n) {
      .Call(C_zufuzz_fdp_bytes, ptr, as.double(n))
    },
    consume_remaining_bytes = function() {
      .Call(C_zufuzz_fdp_bytes, ptr, Inf)
    },
    consume_string = function(n = Inf, encoding = c("utf8", "ascii", "bytes")) {
      encoding <- match.arg(encoding)
      decode_string(.Call(C_zufuzz_fdp_bytes, ptr, as.double(n)), encoding)
    },
    consume_int = function(bits = 32L) {
      .Call(C_zufuzz_fdp_int, ptr, as.integer(bits))
    },
    consume_int_in_range = function(min, max) {
      .Call(C_zufuzz_fdp_int_in_range, ptr, as.double(min), as.double(max))
    },
    consume_number_in_range = function(min, max) {
      .Call(C_zufuzz_fdp_double_in_range, ptr, as.double(min), as.double(max))
    },
    consume_double = function(allow_special = TRUE) {
      .Call(C_zufuzz_fdp_double, ptr, isTRUE(allow_special))
    },
    consume_probability = function() {
      .Call(C_zufuzz_fdp_probability, ptr)
    },
    consume_bool = function() {
      .Call(C_zufuzz_fdp_bool, ptr)
    },
    reset = function() {
      invisible(.Call(C_zufuzz_fdp_reset, ptr))
    }
  )

  # A vector is the natural R value, not a special case, so the list-returning
  # methods ship in 0.1 rather than being deferred as they are in Atheris.
  self$consume_int_list <- function(n, bits = 32L) {
    n <- clamp_count(n)
    if (!n) {
      return(integer(0))
    }
    vapply(seq_len(n), function(i) self$consume_int(bits), integer(1))
  }
  self$consume_double_list <- function(n, allow_special = TRUE) {
    n <- clamp_count(n)
    if (!n) {
      return(numeric(0))
    }
    vapply(seq_len(n), function(i) self$consume_double(allow_special), numeric(1))
  }
  self$consume_probability_list <- function(n) {
    n <- clamp_count(n)
    if (!n) {
      return(numeric(0))
    }
    vapply(seq_len(n), function(i) self$consume_probability(), numeric(1))
  }
  # The second front door onto the same mapping: `draw()` is the first.
  # Implemented in R/objects.R so that spec interpretation and assembly stay
  # readable, while every byte-to-value decision underneath stays in C.
  self$consume_object <- function(spec) {
    consume_object_impl(self, spec)
  }
  self$pick_value <- function(x) {
    if (!length(x)) {
      return(NULL)
    }
    x[[self$consume_int_in_range(1L, length(x))]]
  }

  structure(self, class = "zufuzz_fdp")
}

# A length asked for by fuzzed bytes can be enormous or nonsense. Clamping
# here rather than trusting it is what stops a harness allocating gigabytes
# because four bytes happened to be 0xFFFFFFFF.
clamp_count <- function(n, limit = 1e6) {
  # Length-checked before subscripting. `as.double(NULL)[[1L]]` is "subscript
  # out of bounds", which would break the provider's one promise: nothing
  # errors, on any input. A harness that computes a length and gets
  # integer(0) is not doing anything unreasonable.
  n <- suppressWarnings(as.double(n))
  if (!length(n)) {
    return(0L)
  }
  n <- n[[1L]]
  if (!isTRUE(is.finite(n)) || n <= 0) {
    return(0L)
  }
  as.integer(min(n, limit))
}

#' Decode bytes to a string without ever erroring
#'
#' The documented policy, because a harness needs to know what it is getting:
#'
#' * `utf8` — embedded NULs removed, then the longest valid UTF-8 reading of
#'   what remains, with invalid sequences dropped. Marked UTF-8.
#' * `ascii` — every byte masked to 7 bits, NULs removed.
#' * `bytes` — NULs removed, no re-encoding, no mark.
#'
#' NULs go first in every case because R strings cannot contain them at all:
#' `rawToChar()` errors on an embedded NUL, and that error would belong to the
#' harness rather than the target.
#'
#' @noRd
decode_string <- function(bytes, encoding = "utf8") {
  bytes <- bytes[bytes != as.raw(0)]
  if (!length(bytes)) {
    return("")
  }
  if (identical(encoding, "ascii")) {
    bytes <- as.raw(as.integer(bytes) %% 128L)
    bytes <- bytes[bytes != as.raw(0)]
    if (!length(bytes)) {
      return("")
    }
    return(rawToChar(bytes))
  }

  if (identical(encoding, "bytes")) {
    return(rawToChar(bytes))
  }

  # Filtered in C rather than with iconv(): iconv's handling of malformed
  # input differs between platforms and builds, and "same bytes, same object"
  # has to hold on Linux, macOS and Windows alike or a corpus stops meaning
  # the same thing when it moves between machines.
  kept <- .Call(C_zufuzz_utf8_filter, bytes)
  if (!length(kept)) {
    return("")
  }
  text <- rawToChar(kept)
  Encoding(text) <- "UTF-8"
  text
}

#' @export
print.zufuzz_fdp <- function(x, ...) {
  cat(sprintf(
    "<zufuzz data provider> %.0f byte(s) remaining, %.0f consumed\n",
    x$remaining_bytes(), x$consumed_bytes()
  ))
  invisible(x)
}
