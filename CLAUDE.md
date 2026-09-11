# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

`zufuzz` is a coverage-guided fuzzer for R built the way Atheris (Python) and
Ruzzy (Ruby) are built: libFuzzer vendored into `src/` and driven in-process
through `LLVMFuzzerRunDriver`, with R code instrumented to feed libFuzzer's
8-bit counters and comparison hooks. It is currently an **empty package
skeleton with a complete written design**. There is no bridge, no
instrumentation, no vendored libFuzzer, and no behavioral test suite yet —
only `R/zufuzz-package.R` (package doc + `useDynLib`), `src/zufuzz-package.c`
(headers only), and the standard `tests/testthat.R` runner. `DESCRIPTION`
still holds usethis placeholders.

Work is driven by two documents in [.agents/](.agents/), which are the
authority on intended behavior:

- [.agents/design-zufuzz.md](.agents/design-zufuzz.md) — architecture, API, a
  table of what changed from the first (custom-engine) revision and why, the
  package layering (§15), and native code/sanitizers/preload (§10).
- [.agents/roadmap.md](.agents/roadmap.md) — 15 ordered stages, three gates,
  a parallel native-coverage track, per-stage completion criteria.

Before implementing anything, find the current stage in the roadmap's progress
tracker and read its "Work" and "Complete when" blocks. Stages are sequential
unless marked parallel; do not pull work forward.

## Commands

R 4.6.1, devtools 2.5.2, roxygen2 8.0.0, testthat 3e, air 0.7.0 are installed.

```sh
Rscript -e 'devtools::load_all()'            # load, compiling src/ (incl. vendored libFuzzer once present)
Rscript -e 'devtools::document()'            # roxygen -> NAMESPACE + man/
Rscript -e 'devtools::test()'                # full test suite
Rscript -e 'devtools::test(filter = "fdp")'  # only tests/testthat/test-fdp.R
Rscript -e 'testthat::test_file("tests/testthat/test-fdp.R")'
Rscript -e 'devtools::check()'               # R CMD check, as CI runs it
Rscript -e 'pkgdown::build_site()'           # docs site
air format .                                 # R formatter; run after editing R/
Rscript fuzz/<harness>.R corpus/ -max_len=4096 -runs=1000   # run a harness (once Stage 1 lands)
```

CI (`.github/workflows/R-CMD-check.yaml`) checks macOS/Windows/Ubuntu against
R release, devel, and oldrel-1. The engine builds on Linux/macOS only;
`Makevars.win` must keep the package installable on Windows with
`ZUFUZZ_NO_LIBFUZZER`.

## Working rules

- Run `air format .` after changing R code; `devtools::document()` after
  changing roxygen or native registration.
- Anything that can kill a process (crash fixtures, hangs, `abort()`) is
  tested only in a subprocess via `fuzz_file()`/`processx`, never inside the
  `testthat` process.
- Never patch `src/libfuzzer/`; it is vendored verbatim from the LLVM release
  in `src/libfuzzer/VERSION`. Work around in `src/bridge.cpp`.
- Tests must be deterministic: feedback tests use fixed `-seed`/`-runs` on
  fixtures designed to be solved inside that budget; stochastic discovery
  belongs in `bench/`.
- Keep new APIs internal until the roadmap stage that exports them.
- Long campaigns never run as examples or in `R CMD check`.
- `R CMD check` will NOTE that compiled code calls `abort`/`exit`/writes to
  stderr. That is expected; CRAN is explicitly not a 0.1.0 target.

## Planned architecture

### The model

A harness is an ordinary script: `instrument_package("pkg")`, define
`test_one_input(data)`, call `fuzz(test_one_input)`, run with
`Rscript harness.R corpus/ -flags`. Everything users associate with fuzzing —
mutation, corpus, dictionaries, `-timeout`, `-rss_limit_mb`, `-jobs`/`-fork`,
`-merge`, `-minimize_crash`, `crash-<sha1>` artifacts — is libFuzzer's.
zufuzz implements only: the bridge, R instrumentation, the data provider, and
R-side reproduction tooling. Do not add a mutator, scheduler, corpus store, or
per-input IPC; those were the first design and were dropped deliberately.

### The bridge (`src/bridge.cpp`)

Calls `LLVMFuzzerRunDriver`, which **never returns** (libFuzzer `exit()`s:
0 on budget, 77 on finding, 70 on timeout) — so `fuzz()` ends the R process,
refuses interactive sessions, and only `fuzz_file()` yields a value. The
callback copies bytes into a `RAWSXP` and runs the closure under
`R_UnwindProtect`/`R_tryCatch` so no R `longjmp` crosses libFuzzer's C++
frames. An escaped R error prints a diagnostic, writes a JSON sidecar next to
the future artifact, and calls `abort()` so libFuzzer saves `crash-<sha1>`.
Two R-specific traps: R pre-installs `SIGSEGV`/`SIGILL`/`SIGBUS` (skippable
with `R_NO_SEGV_HANDLER=1` before R starts) and `SIGINT`/`SIGUSR*` handlers,
and libFuzzer will not install over an existing handler (current releases
chain `SIGSEGV` only), so the wrapper sets the env var and the bridge resets
those signals to `SIG_DFL`; and `-fork`/`-jobs`/`-minimize_crash` re-exec
`argv[0]`, so the bridge passes a generated wrapper script that re-runs
`Rscript harness.R`. With nothing instrumented libFuzzer warns "no interesting
inputs" and continues — that is the unguided baseline; do not mask it.

### Instrumentation (`R/instrument.R`, `src/counters.c`)

Selection is `instrument("pkg::fn")`, `instrument_package(pkg, recursive =)`
(the Atheris `instrument_imports()` analogue), or `instrument_all()` — which
**always excludes zufuzz itself**, because the provider and object assembly run
per input and instrumenting them would feed engine execution back as target
coverage. Conservative AST rewrite of selected closures (namespace bindings plus
the S3 methods table; S4/R6/RC are out of scope): probes at function entry, block
statements, both `if` outcomes (synthesized `else` keeps invisible `NULL`),
and loop-body entry. Probes are `.Call(<embedded NativeSymbolInfo>, id)` that
bump `region[id]` in a `uint8_t` region registered once via
`__sanitizer_cov_8bit_counters_init`. Conditions are entered only to rewrite
comparison calls (`==`, `identical`, `%in%`, `startsWith`, string `switch`,
fixed `grepl`) into wrappers that evaluate the original call and forward
operand bytes to libFuzzer's `memcmp`/`strcmp`/`memmem`/`cmp8` hooks — this
is what solves magic-byte checks (always on, unlike Atheris's opt-in
`enabled_hooks`; disable with `instrument(compare = FALSE)`). Other call
arguments are never rewritten
because that changes what `substitute()` sees. `ZUFUZZ_NO_INSTRUMENT=1`
makes `instrument*()` no-ops (used by `replay()`).

### Reproduction (`R/replay.R`, `R/minimize.R`, `R/launcher.R`)

Keep three claims distinct: input reproduction (bytes on disk), finding
reproduction (fresh uninstrumented process reproduces it), campaign
determinism (same flags/seed/corpus → same decisions). `replay()` is
`Rscript harness.R <artifact>` in a fresh process (libFuzzer's run-files-once
mode). `minimize()` drives `-minimize_crash=1` with
`ZUFUZZ_EXPECT_FINGERPRINT` set so the bridge aborts only on the same error
fingerprint — libFuzzer's minimizer otherwise happily switches bugs.
`fuzz_file()` runs a harness under `processx` and classifies the exit into
`budget` / `finding` / `interrupted` / `infrastructure`. `fuzz_function(fn,
corpus, input, expect)` is the one-liner over a package function: it
generates a harness (function resolved by namespace name, narrow `expect`
classes, raw-or-string adapter) and runs it through `fuzz_file()`. It exists
because `fuzz(zujson::parse, corpus = "corpus")` cannot work directly (raw
input, positional corpus, process exit).

### Sanitizers

zufuzz never owns a sanitizer. Two Linux configurations: a sanitized R build
(`rocker/r-devel-san`, `wch1/r-debug`) or stock R + sanitized target +
`LD_PRELOAD` of `preload_path()`. The preload exists because ASan's runtime
defines the sancov callbacks itself (weakly, feeding its own coverage dumper) and the dynamic linker takes
the first definition in search order — the same reason Atheris ships
`asan_with_fuzzer.so`. Always check libFuzzer's "Loaded N modules (M
counters)" line. `fuzz(gc_torture = TRUE)` is the R-specific complement to
ASan for missing-`PROTECT` bugs.

### Layering (design §15)

Four layers, dependencies only ever pointing down: `R/` → `src/bridge.cpp` →
`src/libfuzzer/` for the campaign path; `R/instrument.R` plants probes that
call `src/counters.c`; `R/fdp.R` + `R/objects.R` call `src/fdp.c` **and
nothing else**; `R/launcher.R`/`replay.R`/`minimize.R` use `processx` and no
native code at all. `fdp.c` and `counters.c` must never reference libFuzzer —
that independence is what makes the provider and generator work in a live
session and on Windows, where the engine is absent. Only `fuzz()` calls
`LLVMFuzzerRunDriver`, and it refuses `interactive()`, so nothing a user calls
from a session can take it down.

`draw()` is therefore **not pure R**: R for spec interpretation and object
assembly, C for the byte cursor. The byte→value mapping is implemented once,
in `src/fdp.c`; `draw()` and `fdp$consume_object()` are two front doors onto
it. A second (pure-R) implementation would drift and break "same bytes, same
object". Assembly-in-R vs C is provisional pending Stage 13 benchmarks.

### Structured inputs and object generation

`fuzzed_data_provider()` splits bytes into typed values; `r_object(...)` plus
`fdp$consume_object(spec)` turns the same bytes into R objects so a campaign
can search argument *shape*. The invariant that makes it work: an object is a
pure deterministic function of the bytes — no R RNG, no clock. That is what
lets libFuzzer's mutator edit structure, lets `-minimize_crash` shrink objects,
and lets `draw(spec, n, seed)` generate the same objects **interactively with
no engine loaded**. `as_seed()` saves a drawn object's bytes into a corpus;
`object_from()` renders a crash artifact back into the object. Validity levels
`strict`/`nasty` are in 0.1; `adversarial` (objects that lie about their class
or dim) is deferred because a crash there is a hardening note, not
automatically a defect. Prior art is `hedgehog` and `fuzzr`; neither is
byte-driven, which is why neither composes with coverage guidance.

### Out of scope for 0.1.0

Native coverage as a supported feature (track N decides), `sanitizer_build()`,
an R custom-mutator API, regex hooks, S4/R6/RC instrumentation, the
`adversarial` validity level, Windows fuzzing, CRAN.
