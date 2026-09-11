# The JSON record written next to an artifact.
#
# An artifact is bytes; the sidecar is everything needed to decide what those
# bytes mean and whether the finding still stands. Design section 8 is the
# schema.
#
# One rule with teeth: environment variables are never captured. A fuzzing
# corpus gets committed, attached to issues and shared, and process
# environments hold credentials.

sidecar_schema_version <- "1"

#' SHA-1 of raw bytes, matching libFuzzer's artifact naming
#'
#' @noRd
bytes_digest <- function(bytes) {
  digest::digest(bytes, algo = "sha1", serialize = FALSE)
}

#' The artifact file name for some input
#'
#' `crash-<sha1>` is libFuzzer's convention, kept on every engine so that a
#' corpus and its findings mean the same thing wherever they were produced.
#'
#' @noRd
artifact_name <- function(bytes, kind = "crash") {
  paste0(kind, "-", bytes_digest(bytes))
}

# Versions and library paths, because "it does not reproduce" is usually one
# of these. Deliberately excluded: Sys.getenv(), which is where secrets live.
capture_environment <- function() {
  loaded <- loadedNamespaces()
  versions <- vapply(
    loaded,
    function(p) tryCatch(as.character(utils::packageVersion(p)), error = function(e) NA_character_),
    character(1)
  )
  list(
    r_version = paste(R.version$major, R.version$minor, sep = "."),
    platform = R.version$platform,
    os = Sys.info()[["sysname"]],
    locale = Sys.getlocale("LC_CTYPE"),
    lib_paths = .libPaths(),
    packages = as.list(versions[order(names(versions))])
  )
}

#' Build a sidecar record
#'
#' @noRd
new_sidecar <- function(bytes, kind, fingerprint = NULL, traceback = character(0),
                        harness = NA_character_, rng_seed = NULL,
                        engine = "none", extra = list()) {
  report <- instrumentation_report()
  list(
    schema = sidecar_schema_version,
    kind = kind,
    artifact = artifact_name(bytes, kind),
    sha1 = bytes_digest(bytes),
    length = length(bytes),
    created = format(Sys.time(), "%Y-%m-%dT%H:%M:%S%z"),
    engine = engine,
    fingerprint = if (is.null(fingerprint)) NULL else fingerprint$digest,
    condition = if (is.null(fingerprint)) {
      NULL
    } else {
      list(
        classes = fingerprint$classes,
        message = fingerprint$message,
        call = fingerprint$call
      )
    },
    traceback = traceback,
    harness = list(
      path = harness,
      digest = if (is.na(harness) || !file.exists(harness)) {
        NA_character_
      } else {
        digest::digest(file = harness, algo = "sha1")
      }
    ),
    instrumentation = list(
      version = report$version,
      digest = report$digest,
      sites = report$n_sites,
      functions = report$n_functions,
      jit = report$jit
    ),
    rng_seed = rng_seed,
    environment = capture_environment(),
    extra = extra
  )
}

#' Write an artifact and its sidecar
#'
#' @return The artifact path, invisibly.
#' @noRd
write_artifact <- function(bytes, sidecar, dir) {
  dir.create(dir, recursive = TRUE, showWarnings = FALSE)
  path <- file.path(dir, sidecar$artifact)
  writeBin(bytes, path)
  # auto_unbox so a scalar reads as a scalar rather than a one-element array;
  # null so an absent fingerprint is null rather than missing, which keeps the
  # shape stable for anything reading it.
  jsonlite::write_json(
    sidecar,
    paste0(path, ".json"),
    auto_unbox = TRUE,
    null = "null",
    pretty = TRUE
  )
  invisible(path)
}

#' @noRd
read_sidecar <- function(artifact_path) {
  json <- paste0(artifact_path, ".json")
  if (!file.exists(json)) {
    return(NULL)
  }
  jsonlite::read_json(json, simplifyVector = TRUE)
}

# The fields anything reading a sidecar is entitled to find. Checked in tests
# rather than asserted at write time: a sidecar is written on a failure path,
# and refusing to record a finding because a field is missing would lose the
# finding.
sidecar_required_fields <- c(
  "schema", "kind", "artifact", "sha1", "length", "created",
  "engine", "traceback", "harness", "instrumentation", "environment"
)

#' @noRd
sidecar_missing_fields <- function(sidecar) {
  setdiff(sidecar_required_fields, names(sidecar))
}

# Differences that explain "it did not reproduce". Reported, never fatal:
# a finding from a different R build is still worth looking at.
#' @noRd
environment_mismatches <- function(recorded, current = capture_environment()) {
  if (is.null(recorded)) {
    return(character(0))
  }
  out <- character(0)
  for (field in c("r_version", "platform", "os")) {
    was <- recorded[[field]]
    now <- current[[field]]
    if (!is.null(was) && !identical(as.character(was), as.character(now))) {
      out <- c(out, sprintf("%s: recorded %s, now %s", field, was, now))
    }
  }
  recorded_pkgs <- recorded$packages
  if (length(recorded_pkgs)) {
    shared <- intersect(names(recorded_pkgs), names(current$packages))
    for (p in shared) {
      was <- as.character(recorded_pkgs[[p]])
      now <- as.character(current$packages[[p]])
      if (!identical(was, now)) {
        out <- c(out, sprintf("package %s: recorded %s, now %s", p, was, now))
      }
    }
  }
  out
}
