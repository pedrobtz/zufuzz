# zufuzz

<!-- badges: start -->
[![R-CMD-check](https://github.com/pedrobtz/zufuzz/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/zufuzz/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

Coverage-guided fuzzing for R packages, in the spirit of
[Atheris](https://github.com/google/atheris) for Python and
[Ruzzy](https://github.com/trailofbits/ruzzy) for Ruby.

Write a small function that takes bytes and does something with them. zufuzz
instruments your package so that reaching a new branch is visible, hands the
bytes to a fuzzing engine, and turns anything that goes wrong into a
reproducible artifact.

**zufuzz contains no fuzzing engine.** Instrumentation, structured input
generation, replay, minimization and coverage reporting all work with nothing
else installed, on Linux, macOS and Windows. Running a *campaign* needs an
engine, and `engines()` will tell you which you have.

## Installation

```r
install.packages("zufuzz")
```

## A harness

A harness is an ordinary R script.

```r
library(zufuzz)
library(zujson)

instrument_package("zujson")

test_one_input <- function(data) {
  fdp <- fuzzed_data_provider(data)
  text <- fdp$consume_string(fdp$remaining_bytes())

  parsed <- tryCatch(zujson::parse(text), zujson_error = function(e) NULL)
  if (!is.null(parsed)) {
    # Invalid input may be rejected. A failed round trip may not.
    stopifnot(identical(zujson::parse(zujson::serialize(parsed)), parsed))
  }
}

fuzz(test_one_input, engine = "auto")
```

Two rules make the difference between a harness that finds bugs and one that
finds noise:

* **Catch expected rejections narrowly**, around the call that is allowed to
  reject, naming the condition class. Wrapping the whole body in
  `tryCatch(..., error = function(e) NULL)` catches the defects too.
* **Any `error` that escapes is a finding.** That is the oracle.

## Running it

The same file runs three ways, unchanged.

```sh
# Run specific inputs once. No engine needed, works everywhere.
Rscript harness.R corpus/seed-01 crash-3f2a...

# A campaign under AFL++.
afl-fuzz -i corpus -o out -- Rscript harness.R
```

```r
# Or from R, in a child process, so a finding does not end your session.
fuzz_file("harness.R", corpus = "corpus", time_limit = 60)
```

`engine = "auto"` picks the best available: an attached supervisor if there is
one, otherwise run-once.

## What you get

```r
res <- fuzz_file("harness.R", corpus = "corpus", time_limit = 60)
res$stop_reason
#> [1] "finding"

res$finding$artifact
#> [1] ".zufuzz/artifacts/crash-9c1185a5c5e9fc54612808977ee8f548b2258d31"
```

Every finding is bytes on disk plus a JSON sidecar recording the condition,
a fingerprint, a bounded traceback, the instrumentation digest and the
versions in play — but never your environment variables, because corpora get
committed and shared.

Then confirm it in a fresh, uninstrumented process:

```r
replay("harness.R", res$finding$artifact)
#> <zufuzz replay> error
#>   fingerprint 4a7d1ed414
#>   confirms the recorded finding
```

and shrink it without changing which bug it is:

```r
minimize("harness.R", res$finding$artifact)
#> <zufuzz minimize> 4096 -> 12 bytes in 141 run(s)
#>   fingerprint 4a7d1ed414 (unchanged)
```

That last property is the reason `minimize()` is not a wrapper around
`afl-tmin`: those tools only know whether the target died, so they will
happily shrink one bug into a different, smaller one and call it success.
Every candidate here is confirmed against the original fingerprint.

## Structured input

Most R functions take objects, not bytes.

```r
spec <- r_object(types = c("integer", "character", "list"), max_len = 8)

test_one_input <- function(data) {
  x <- fuzzed_data_provider(data)$consume_object(spec)
  summary(x)
}
```

An object is a pure, deterministic function of the bytes — no RNG, no clock.
That is what lets the engine's mutations edit *structure*, lets `minimize()`
shrink an object by shrinking its bytes, and lets you explore a spec by hand
with no engine at all:

```r
xs <- draw(spec, n = 20, seed = 42)
as_seed(xs[[7]], "corpus")            # keep an interesting shape
object_from("crash-3f2a...", spec)    # see the object behind a crash
```

## Engines

```r
engines()
#> <zufuzz engines>
#>   none       yes   built in
#>   afl        yes   /opt/homebrew/bin/afl-fuzz (PATH)
#>   libfuzzer   no   provided by the zufuzz.libfuzzer companion package (not yet released)
```

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| instrument, generate, replay, minimize, coverage | yes | yes | yes |
| campaign under AFL++ | yes | yes, with caveats | no |
| campaign in-process (libFuzzer) | companion package | companion package | no |

On Windows everything except a campaign works. No fuzzing engine runs under
Rtools, so campaigns need WSL or a container — but you can still instrument,
generate objects, replay an artifact someone else found, and minimize it.

## What zufuzz does not do

It implements no mutator, no corpus scheduler and no timeout supervisor.
Those belong to the engine, which is much better at them. zufuzz implements
the R instrumentation, the counter sink, the data provider and object
generator, the launcher, and the reproduction tooling.

## Related work

[`hedgehog`](https://cran.r-project.org/package=hedgehog) and
[`fuzzr`](https://cran.r-project.org/package=fuzzr) also generate awkward
inputs, and `hedgehog` does property-based testing well. The difference is the
driver: QuickCheck-style generators consume an RNG and shrink through their
own algebra, which coverage cannot steer. zufuzz's generator consumes *bytes*,
so an engine's feedback loop and its minimizer apply directly. Use `hedgehog`
for expressive properties over well-formed values; use zufuzz when you want
coverage to find the shape, or when native code is involved.
