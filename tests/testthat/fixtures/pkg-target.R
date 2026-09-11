# A stand-in "package function" for fuzz_function(): rejects bad input with a
# specific condition class, and has one planted defect that is NOT in that
# class. A campaign should report the second and ignore the first.
parse_pair <- function(text) {
  if (!nzchar(text)) {
    stop(structure(
      class = c("pair_error", "error", "condition"),
      list(message = "empty input", call = NULL)
    ))
  }
  if (startsWith(text, "!")) {
    stop("planted defect: unexpected bang")
  }
  strsplit(text, "=", fixed = TRUE)[[1L]]
}
