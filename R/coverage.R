# Reading the counters back against the site map.
#
# This is a report, not feedback. The engine reads the region itself; this
# turns it into something a person can act on, and it is what `coverage_out`
# writes in Stage 4.
#
# It works with no engine attached, which is the point: "what does this corpus
# reach" is answerable in a plain session, on Windows, and inside R CMD check.

#' Sites and their hit counts
#'
#' @return A data frame of function, site id, kind, path and hits, or an empty
#'   frame when nothing is instrumented.
#' @noRd
coverage_sites <- function() {
  plan <- state$plan
  if (is.null(plan) || !plan$n_sites) {
    return(rows_to_df(list(), c("function", "id", "kind", "path")))
  }
  sites <- plan_sites(plan)
  hits <- counter_hits()
  # Site ids are dense from zero; the region is sized from the same plan, so
  # a mismatch here means the region was resized behind the plan's back.
  if (length(hits) < plan$n_sites) {
    stop(
      "zufuzz: the counter region is smaller than the plan that sized it",
      call. = FALSE
    )
  }
  sites$hits <- hits[sites$id + 1L]
  sites
}

#' A one-line summary of what a run reached
#'
#' @noRd
coverage_summary <- function(sites = coverage_sites()) {
  total <- nrow(sites)
  reached <- if (total) sum(sites$hits > 0L) else 0L
  list(
    sites = total,
    reached = reached,
    proportion = if (total) reached / total else NA_real_
  )
}

#' Which sites a run reached, as "function@path" labels
#'
#' Deliberately not ids: an id is stable only within one plan, and a test that
#' asserts ids would pass for the wrong reason if placement changed.
#'
#' @noRd
coverage_reached <- function(sites = coverage_sites()) {
  if (!nrow(sites)) {
    return(character(0))
  }
  hit <- sites[sites$hits > 0L, , drop = FALSE]
  paste0(hit[["function"]], "@", hit$kind, "@", hit$path)
}
