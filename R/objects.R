# Bytes to R objects.
#
# Most R functions take objects, not bytes. A generator that turns the same
# fuzzed bytes into vectors, lists and attributes lets a campaign search the
# *shape* of an argument rather than only its contents.
#
# The rule everything here rests on (design section 11):
#
#   An object is a pure, deterministic function of the bytes. No RNG, no
#   clock, no environment.
#
# That single rule buys four things, and losing it loses all four: an engine's
# mutations become structural edits; minimize() shrinks the object by
# shrinking its bytes; every object has an exact on-disk representation that
# replays; and the same generator runs in a plain session with no engine.

generator_version <- "1"

object_types <- c("logical", "integer", "double", "character", "list", "NULL")

#' Describe the objects a campaign should generate
#'
#' A declarative spec rather than a generator closure, so it can be printed,
#' compared, and recorded in a finding's metadata -- which is what makes a
#' crash report say what kind of object caused it.
#'
#' @param types Which types may be generated.
#' @param max_len Longest vector or list to build.
#' @param max_depth How deep lists may nest.
#' @param validity `"strict"` builds only what base constructors produce.
#'   `"nasty"` adds the values that are representable and legal but that most
#'   code forgets: `NA` of every type, `NaN`, `±Inf`, `-0`, zero-length
#'   vectors, names, encoding marks, and both ALTREP and materialized forms of
#'   the same value. A crash at either level is a defect.
#' @param names Whether generated vectors and lists may carry names.
#' @return An `r_object_spec`.
#' @export
#' @examples
#' spec <- r_object(types = c("integer", "character"), max_len = 8)
#' draw(spec, n = 2, seed = 1)
r_object <- function(types = c("logical", "integer", "double", "character", "list"),
                     max_len = 16L,
                     max_depth = 3L,
                     validity = c("nasty", "strict"),
                     names = TRUE) {
  validity <- match.arg(validity)
  unknown <- setdiff(types, object_types)
  if (length(unknown)) {
    stop(
      "zufuzz: unknown type(s) ", paste(sQuote(unknown), collapse = ", "),
      call. = FALSE
    )
  }
  if (!length(types)) {
    stop("zufuzz: a spec needs at least one type", call. = FALSE)
  }
  structure(
    list(
      version = generator_version,
      types = types,
      max_len = max(0L, as.integer(max_len)),
      max_depth = max(0L, as.integer(max_depth)),
      validity = validity,
      names = isTRUE(names)
    ),
    class = "r_object_spec"
  )
}

#' @export
print.r_object_spec <- function(x, ...) {
  cat(sprintf(
    "<r_object spec> %s, max_len %d, max_depth %d, names %s\n",
    x$validity, x$max_len, x$max_depth, if (x$names) "yes" else "no"
  ))
  cat("  types:", paste(x$types, collapse = ", "), "\n")
  invisible(x)
}

# -- assembly ------------------------------------------------------------

consume_object_impl <- function(fdp, spec, depth = 0L) {
  if (!inherits(spec, "r_object_spec")) {
    stop("zufuzz: `spec` must come from r_object()", call. = FALSE)
  }
  # Lists are only offered while there is depth left, so recursion is bounded
  # by the spec rather than by how the bytes happen to fall.
  available <- spec$types
  if (depth >= spec$max_depth) {
    available <- setdiff(available, "list")
  }
  if (!length(available)) {
    available <- "NULL"
  }

  type <- available[[fdp$consume_int_in_range(1L, length(available))]]
  n <- fdp$consume_int_in_range(0L, spec$max_len)

  value <- switch(type,
    NULL = NULL,
    logical = consume_logical(fdp, n, spec),
    integer = consume_integer(fdp, n, spec),
    double = consume_numeric(fdp, n, spec),
    character = consume_character(fdp, n, spec),
    list = lapply(seq_len(n), function(i) consume_object_impl(fdp, spec, depth + 1L)),
    NULL
  )

  if (is.null(value)) {
    return(NULL)
  }
  if (spec$names && length(value) && fdp$consume_bool()) {
    names(value) <- consume_names(fdp, length(value), spec)
  }
  value
}

nasty <- function(spec) identical(spec$validity, "nasty")

consume_logical <- function(fdp, n, spec) {
  if (!n) {
    return(logical(0))
  }
  vapply(seq_len(n), function(i) {
    # NA is legal in every logical vector and is the single most common thing
    # R code forgets to handle, so `nasty` reaches it often rather than rarely.
    if (nasty(spec) && fdp$consume_int_in_range(0L, 3L) == 0L) NA else fdp$consume_bool()
  }, logical(1))
}

consume_integer <- function(fdp, n, spec) {
  if (!n) {
    return(integer(0))
  }
  vapply(seq_len(n), function(i) {
    if (nasty(spec) && fdp$consume_int_in_range(0L, 5L) == 0L) {
      return(NA_integer_)
    }
    fdp$consume_int()
  }, integer(1))
}

consume_numeric <- function(fdp, n, spec) {
  if (!n) {
    return(numeric(0))
  }
  # consume_double(allow_special =) already reaches NaN, +-Inf, NA_real_ and
  # -0 through one byte, so `nasty` is exactly "let it".
  vapply(seq_len(n), function(i) fdp$consume_double(allow_special = nasty(spec)), numeric(1))
}

consume_character <- function(fdp, n, spec) {
  if (!n) {
    return(character(0))
  }
  out <- vapply(seq_len(n), function(i) {
    if (nasty(spec) && fdp$consume_int_in_range(0L, 5L) == 0L) {
      return(NA_character_)
    }
    fdp$consume_string(fdp$consume_int_in_range(0L, 16L))
  }, character(1))

  if (nasty(spec) && length(out) && fdp$consume_bool()) {
    # An encoding mark changes which branch of most string code runs, and
    # `latin1` versus `UTF-8` is a real source of defects that never shows up
    # with ASCII-only test data.
    mark <- c("UTF-8", "latin1", "bytes")[fdp$consume_int_in_range(1L, 3L)]
    marked <- tryCatch(
      {
        Encoding(out) <- mark
        out
      },
      error = function(e) out
    )
    out <- marked
  }
  out
}

consume_names <- function(fdp, n, spec) {
  vapply(seq_len(n), function(i) {
    if (nasty(spec) && fdp$consume_int_in_range(0L, 7L) == 0L) {
      # Empty and duplicated names are legal and are what breaks code that
      # assumes names are unique keys.
      return("")
    }
    nm <- fdp$consume_string(fdp$consume_int_in_range(0L, 8L))
    if (!nzchar(nm)) "" else nm
  }, character(1))
}

# -- the interactive surface ---------------------------------------------

#' Generate objects from a spec, without an engine
#'
#' The same machinery a campaign uses, driven by hand. `draw()` needs no
#' engine, no worker and no instrumentation, which is what makes it usable for
#' exploring a spec before committing a campaign to it.
#'
#' @param spec An [r_object()] spec.
#' @param n How many objects to draw.
#' @param seed Integer. Expanded to bytes through an internal PRNG that never
#'   touches `.Random.seed`, so drawing is reproducible without disturbing the
#'   caller's random stream.
#' @param bytes Raw vector to draw from instead of a seed. This is how an
#'   exact object is reproduced.
#' @return A list of objects, each carrying the bytes that produced it in a
#'   `zufuzz_bytes` attribute.
#' @export
#' @examples
#' spec <- r_object(types = c("integer", "logical"), max_len = 4)
#' xs <- draw(spec, n = 3, seed = 42)
#' str(xs)
draw <- function(spec, n = 1L, seed = NULL, bytes = NULL) {
  if (!inherits(spec, "r_object_spec")) {
    stop("zufuzz: `spec` must come from r_object()", call. = FALSE)
  }
  n <- max(0L, as.integer(n))

  if (!is.null(bytes)) {
    # Exact reproduction: one byte vector, one object.
    obj <- fuzzed_data_provider(bytes)$consume_object(spec)
    attr(obj, "zufuzz_bytes") <- as.raw(bytes)
    return(list(obj))
  }

  if (is.null(seed)) {
    # Still not R's RNG: a drawn object must be reproducible from its bytes,
    # and taking entropy from .Random.seed would make "same bytes, same
    # object" depend on session state.
    seed <- as.integer(Sys.time()) %% .Machine$integer.max
  }

  lapply(seq_len(n), function(i) {
    b <- expand_seed(seed, i, bytes_needed(spec))
    obj <- fuzzed_data_provider(b)$consume_object(spec)
    attr(obj, "zufuzz_bytes") <- b
    obj
  })
}

# Enough bytes that a spec is rarely truncated mid-object. Truncation is not
# an error -- exhaustion is a value -- but it biases draws toward short ones.
bytes_needed <- function(spec) {
  as.integer(min(65536, 64 + spec$max_len * (spec$max_depth + 1L) * 32L))
}

# A small LCG, written out rather than borrowed, because the point is that it
# cannot touch .Random.seed and cannot change underneath a recorded corpus:
# same seed, same bytes, in any session and any R version.
#
# Arithmetic is in doubles, which hold integers exactly below 2^53. R's
# integers are 32-bit and signed, so the obvious version overflows to NA --
# quietly, since `2654435761L` is not even representable and `a * b %% m`
# parses as `a * (b %% m)`. Both of those bit here before this comment existed.
expand_seed <- function(seed, stream, n) {
  modulus <- 4294967296 # 2^32
  state <- (as.double(seed) %% modulus +
    (as.double(stream) * 2654435761) %% modulus) %% modulus
  if (state == 0) {
    state <- 1
  }
  out <- raw(n)
  for (i in seq_len(n)) {
    # Numerical Recipes constants. The product stays under 2^53, so it is
    # exact; the high bits are taken because an LCG's low bits are poor.
    state <- (1664525 * state + 1013904223) %% modulus
    out[[i]] <- as.raw(floor(state / 16777216))
  }
  out
}

#' Save a drawn object's bytes as a corpus seed
#'
#' Explore a spec interactively, keep the shapes that look interesting, and
#' start a campaign from them.
#'
#' @param x An object from [draw()].
#' @param corpus Corpus directory; created if needed.
#' @return The path written, invisibly.
#' @export
as_seed <- function(x, corpus) {
  bytes <- attr(x, "zufuzz_bytes")
  if (is.null(bytes)) {
    stop(
      "zufuzz: this object did not come from draw(), so the bytes behind it ",
      "are not known",
      call. = FALSE
    )
  }
  dir.create(corpus, recursive = TRUE, showWarnings = FALSE)
  path <- file.path(corpus, bytes_digest(bytes))
  writeBin(bytes, path)
  invisible(path)
}

#' Render a crash artifact back into the object that caused it
#'
#' Triage then inspects a value rather than a hexdump.
#'
#' @param artifact Path to an artifact.
#' @param spec The spec the harness used.
#' @return The object those bytes generate.
#' @export
object_from <- function(artifact, spec) {
  if (!file.exists(artifact)) {
    stop("zufuzz: no such artifact: ", artifact, call. = FALSE)
  }
  bytes <- read_input(artifact)
  obj <- fuzzed_data_provider(bytes)$consume_object(spec)
  attr(obj, "zufuzz_bytes") <- bytes
  obj
}
