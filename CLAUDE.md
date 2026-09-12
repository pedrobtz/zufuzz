# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

`zufuzz` is a coverage-guided fuzzer for R in the spirit of Atheris (Python)
and Ruzzy (Ruby): instrument R code so probes feed a counter region, write a
`test_one_input(data)` harness, and let a fuzzing engine drive it. Unlike
those two, **the engine is not in this package**. This repository is the CRAN
package: engine-neutral, no C++, no vendored engine, and no compiled code that
can terminate R. Engines attach from outside through two seams.

It is currently **eleven and a half of fourteen stages complete and merged**
(Stage 10's worker path landed; its preload half is blocked), with a
working tool: it instruments R code, runs campaigns under AFL++ or run-once
anywhere, writes crash artifacts with JSON sidecars, replays and minimizes
findings, generates structured R objects deterministically, and proves the
whole pipeline on every push with a real bounded campaign in CI
(`.github/workflows/fuzz-smoke.yaml`). ~7760 tests; `R CMD check --as-cran`
is 0 errors, 0 warnings, and notes that are documented in `cran-comments.md`.

**What is left, and why it is blocked.** Stage 9 (comparison tracing),
Stage 10's preload half, Gate B's engine half and Stage 12's
guided-vs-unguided arm all need the `zufuzz.libfuzzer` companion package —
a second, non-CRAN package holding the vendored libFuzzer and the
`abort()`-calling bridge. **That repository does not exist yet.** Stage 13
additionally needs a real name in `Authors@R`; it is still the placeholder
`person("pedrobtz", ...)`, which CRAN will reject.

Before starting anything, read the roadmap's progress tracker: each finished
stage records what was settled and what was found the hard way, and several
criteria were amended with reasons rather than met. Do not re-litigate those
without reading them.

Work is driven by two documents in [.agents/](.agents/), which are the
authority on intended behavior:

- [.agents/design-zufuzz.md](.agents/design-zufuzz.md) — third revision.
  Architecture, API, the execution models (§4), coverage sinks (§6), CRAN and
  companion packaging rules (§13), layering (§15), sanitizers (§10), and two
  tables of what changed between revisions and why (§1).
- [.agents/roadmap.md](.agents/roadmap.md) — Stages 0–13 for this package, a
  separate companion track E0–E3, three gates, a parallel native-coverage
  track, per-stage completion criteria.

Before implementing anything, find the current stage in the roadmap's progress
tracker and read its "Work" and "Complete when" blocks. Stages are sequential
unless marked parallel; do not pull work forward.

§1's decision tables record *why* each engine and packaging choice was made,
with the measurement behind it. Read them before proposing an alternative —
LibAFL, clang-supplied libFuzzer, and an in-package engine were all evaluated
and rejected for specific, recorded reasons.

## The two packages

| | this repo — `zufuzz` | `zufuzz.libfuzzer` (separate repo) |
| --- | --- | --- |
| Ships on | **CRAN** | r-universe only |
| Contains | R, plus `counters.c`, `protocol_afl.c`, `fdp.c`, `init.c` | vendored libFuzzer, `bridge.cpp` |
| Platforms | Linux, macOS, **Windows** | Linux, macOS |
| `exit`/`abort`/stdio in compiled code | **never** | yes, by design |

Engines reach this package three ways: the companion package
(`Suggests:` + `Additional_repositories:`), an `afl-fuzz` binary on `PATH`
(`SystemRequirements:`), or nothing at all — in which case everything except
running a campaign still works.

## Commands

R 4.6.1, devtools 2.5.2, roxygen2 8.1.0, testthat 3e are installed. **`air` is
not** — the working rule below still applies, but the formatter has to be
installed before it can be run. No fuzzing engine is installed here either;
that is the configuration CI judges, so develop in it.

```sh
Rscript -e 'devtools::load_all()'            # load, compiling src/
Rscript -e 'devtools::document()'            # roxygen -> NAMESPACE + man/
Rscript -e 'devtools::test()'                # full test suite
Rscript -e 'devtools::test(filter = "fdp")'  # only tests/testthat/test-fdp.R
Rscript -e 'testthat::test_file("tests/testthat/test-fdp.R")'
Rscript -e 'devtools::check()'               # R CMD check --as-cran (cran = TRUE is the default)
Rscript -e 'pkgdown::build_site()'           # docs site
air format .                                 # R formatter; run after editing R/
Rscript -e 'zufuzz::engines()'               # which engines are available and where
```

Running a harness — the same file, three ways, unchanged:

```sh
Rscript fuzz/<harness>.R crash-3f2a...                        # run-once; no engine
afl-fuzz -i corpus -o .zufuzz/afl -- Rscript fuzz/<harness>.R # AFL++ worker
Rscript inst/smoke/run-smoke.R                                # the CI smoke campaign
```

CI (`.github/workflows/R-CMD-check.yaml`) checks macOS/Windows/Ubuntu against
R release, devel, and oldrel-1, all with **no engine installed** — that is the
configuration CRAN checks in. One extra Ubuntu job installs `afl++` from apt
and runs the engine-dependent tests; the companion job will join it when that
package exists.

The bar is **no errors, no warnings, and only notes that are documented and
justified** — not zero notes. Two are expected and correct: `unlockBinding`
(replacing a binding in a locked namespace is what an instrumentation package
does) and CRAN-incoming (new submission, dev version, unpublished pkgdown
URL). `cran-comments.md` explains both. Making the first vanish via
`get("unlockBinding", baseenv())` would hide binding surgery from a reviewer;
do not.

`.github/workflows/fuzz-smoke.yaml` runs a real bounded campaign on every
push, because `R CMD check` must never start one.

## Working rules

- Run `air format .` after changing R code; `devtools::document()` after
  changing roxygen or native registration.
- **`zufuzz.so` must never reference `exit`, `_exit`, `abort`, stdio writes,
  or any `__sanitizer_*` symbol.** A symbol-scan test enforces this from
  Stage 0. It is simultaneously the CRAN gate (no compiled-code NOTE) and the
  layering gate (no engine dependency in the value layer). If a task seems to
  need one of those calls, the task belongs in the companion package.
- Anything that can kill a process (crash fixtures, hangs, `pskill`,
  `abort()`) is tested only in a subprocess via `fuzz_file()`/`processx`,
  never inside the `testthat` process.
- Every engine-dependent test is `skip_if_not(engine_available(...))`; every
  campaign example is under `@examplesIf`. `R CMD check` must pass on a
  machine with no engine, and must never start a campaign.
- Tests write only under `tempdir()`. `.zufuzz/` is created by `fuzz()` and
  `fuzz_file()`, never by a test or example.
- Tests must be deterministic: feedback tests use fixed seeds and budgets
  (`-seed`/`-runs`, or AFL's `-s`/`-E`) on fixtures designed to be solved
  inside that budget; stochastic discovery belongs in `bench/`.
- Drive the launcher with real harness fixtures rather than a mock. The
  roadmap called for a fake supervisor at Stage 5; it turned out unnecessary,
  because run-once is itself a real engine and ordinary fixtures produce every
  `stop_reason`. Simulating a supervisor would test the simulation.
- Keep new APIs internal until the roadmap stage that exports them.
- CRAN **is** a 0.1.0 target for this package. Weigh CRAN policy — no
  install-time downloads, no shipped binaries, writes only to
  `tools::R_user_dir()` with consent — before adding anything.

## Architecture

### The model

A harness is an ordinary script: `instrument_package("pkg")`, define
`test_one_input(data)`, call `fuzz(test_one_input)`. The *same file* runs
under every engine and under none. Everything users associate with fuzzing —
mutation, corpus, dictionaries, timeouts, memory limits, parallel jobs,
`crash-<sha1>` artifacts — belongs to the engine. zufuzz implements only: R
instrumentation, the counter sink, the data provider and object generator, the
launcher, the R-side reproduction tooling, and the *child* half of one
worker-engine protocol. Do not add a mutator, scheduler, or corpus store;
those were the first design and were dropped deliberately, and a minimal
in-package engine (the only route to native Windows campaigns) is still
rejected for the same reason.

### Three execution models (design §4)

`fuzz(engine =)` selects one. Only the first two are in this repo.

- **Run-once** (`engine = "none"`, any platform, no engine): read each
  positional file, run the closure under `tryCatch`, record hits, write
  `coverage_out`, **return**. Never kills the process. This is what `replay()`
  is built on and what makes coverage reporting testable inside `R CMD check`.
- **Worker** (`engine = "afl"`, Linux/macOS): `shmat` AFL's 64 KiB bitmap,
  deferred fork server on fds 198/199, then a `repeat` loop **in R**. An
  escaped error writes the sidecar and calls
  `tools::pskill(Sys.getpid(), tools::SIGABRT)` — base R, no compiled
  `abort()`. C routines are leaves that never evaluate R, so no
  `R_UnwindProtect` is needed here. Modelled on python-afl (235 lines).
- **In-process** (`engine = "libfuzzer"`, companion package): `bridge.cpp`
  calls `LLVMFuzzerRunDriver`, which never returns (libFuzzer `exit()`s: 0 on
  budget, 77 on finding, 70 on timeout). The callback runs the closure under
  `R_UnwindProtect`/`R_tryCatch` so no R `longjmp` crosses C++ frames; an
  escaped error `abort()`s. R pre-installs `SIGSEGV`/`SIGILL`/`SIGBUS`
  (skippable with `R_NO_SEGV_HANDLER=1` before R starts) and `SIGINT`/`SIGUSR*`
  handlers, and libFuzzer will not install over an existing handler, so the
  wrapper sets the env var and the bridge resets those signals to `SIG_DFL`.
  `-fork`/`-jobs`/`-minimize_crash` re-exec `argv[0]`, so a generated wrapper
  script re-runs `Rscript harness.R`.

Both campaign modes refuse `interactive()`. With nothing instrumented,
libFuzzer warns "no interesting inputs" and AFL reports no new paths — that is
the unguided baseline and the control arm for Gate C; do not mask it.

### Instrumentation (`R/instrument.R`, `src/counters.c`)

Selection is `instrument("pkg::fn")`, `instrument_package(pkg, recursive =)`
(the Atheris `instrument_imports()` analogue), or `instrument_all()` — which
**always excludes zufuzz itself**, because the provider, object assembly, and
worker loop run per input and instrumenting them would feed engine execution
back as target coverage. Conservative AST rewrite of selected closures
(namespace bindings plus the S3 methods table; S4/R6/RC are out of scope):
probes at function entry, block statements, both `if` outcomes (synthesized
`else` keeps invisible `NULL`), and loop-body entry.

Probes are `.Call(<embedded NativeSymbolInfo>, id)` into a routine with three
**sink modes**, fixed when an engine attaches:

| mode | probe body | region registered by |
| --- | --- | --- |
| `none` | `region[id]++` | nobody; read by `coverage_out` |
| `afl` | `map[id ^ prev]++; prev = id >> 1` | the attached supervisor's shm |
| `libfuzzer` | `region[id]++` | the companion, via an exported accessor |

**`counters.c` references no `__sanitizer_*` symbol in any mode.**
Registration is the companion's job. That one rule is what keeps this package
on CRAN, and what lets a sanitized R build be an AFL++ worker with nothing
preloaded. Dense site IDs (Stage 2) also make the AFL edge map
collision-free below 64 K sites — better than python-afl's hashing.

Conditions are entered only to rewrite comparison calls (`==`, `identical`,
`%in%`, `startsWith`, string `switch`, fixed `grepl`) into wrappers that
evaluate the original call and forward operand bytes to
`memcmp`/`strcmp`/`memmem`/`cmp8` hooks — this is what solves magic-byte
checks (always on, unlike Atheris's opt-in `enabled_hooks`; disable with
`instrument(compare = FALSE)`). The forwarding bodies are the companion's;
under `none`/`afl` they are no-ops in 0.1 (AFL CmpLog is 0.2). Other call
arguments are never rewritten because that changes what `substitute()` sees.
`ZUFUZZ_NO_INSTRUMENT=1` makes `instrument*()` no-ops (used by `replay()`).

### Reproduction (`R/replay.R`, `R/minimize.R`, `R/launcher.R`)

Keep three claims distinct: input reproduction (bytes on disk), finding
reproduction (fresh uninstrumented process reproduces it), campaign
determinism (same engine/flags/seed/corpus → same decisions).

`replay()` and `minimize()` are **engine-neutral and work on Windows**, since
both run zufuzz's own run-once mode. `minimize()` is an R-side delta-debugging
reducer whose every candidate is confirmed by `replay()` with
`ZUFUZZ_EXPECT_FINGERPRINT` set — the gate that keeps it from switching bugs,
which neither `-minimize_crash` nor `afl-tmin` has. Those two are optional
accelerators (`accelerate = TRUE`) that run first; the gated reducer always
finishes the job.

`fuzz_file()` runs a harness under `processx` and classifies into `budget` /
`finding` / `interrupted` / `infrastructure`. **Classification reads the
artifact directory; the exit code only corroborates** — engines disagree about
exit codes and none of them is ground truth. Artifact names (`crash-<sha1>`,
sidecars, SHA-1 via `digest`) are identical on every engine; AFL's
`crashes/id:*` are imported into `.zufuzz/artifacts/` and AFL's own directory
is left untouched so `afl-cmin`/`afl-tmin` keep working.

`fuzz_function(fn, corpus, input, expect)` is the one-liner over a package
function: it generates a harness (function resolved by namespace name, narrow
`expect` classes, raw-or-string adapter) and runs it through `fuzz_file()`. It
exists because `fuzz(zujson::parse, corpus = "corpus")` cannot work directly
(raw input, positional corpus, process exit).

### Sanitizers

zufuzz never owns a sanitizer. **The recommended 0.1 configuration is the
worker path**: run `afl-fuzz` over a sanitized R build (`rocker/r-devel-san`,
`wch1/r-debug`). No libFuzzer is in the process and `counters.c` references no
sancov symbol, so there is no symbol conflict and nothing is preloaded.

`R/sanitizer.R` reads a report out of a dead process's log -- kind, category,
`SUMMARY:`, top frames, signal -- and fingerprints it as kind + category +
the top frame that is neither a sanitizer interceptor nor an R evaluator
frame. Three rules there are load-bearing and were each learned the hard way:
UBSan's `SUMMARY` has **no `in <function>` part**, a LeakSanitizer report is a
configuration fault rather than a finding (zufuzz disables LSan on purpose),
and the fingerprint must exclude the build path or every reproduction in a
different tree reads as a different bug. A bare signal is recorded but never
fingerprinted, so `minimize()` refuses it. `sanitizer_status()` reports
`sanitized` only when the runtime is mapped into the process; build flags and
`LD_PRELOAD` are evidence, not proof. Fixtures in
`tests/testthat/fixtures/sanitizer/` are real clang output -- do not replace
them with invented text. See `vignette("sanitizers")`.

The companion's in-process path needs the preload: ASan's runtime defines the
sancov callbacks itself (weakly, feeding its own coverage dumper) and the
dynamic linker takes the first definition in search order — the same reason
Atheris ships `asan_with_fuzzer.so`. There, always check libFuzzer's "Loaded N
modules (M counters)" line. `fuzz(gc_torture = TRUE)` is the R-specific
complement to ASan for missing-`PROTECT` bugs, on any engine.

### Layering (design §15)

Dependencies point down and never cross the package boundary upward:
`R/instrument.R` plants probes that call `src/counters.c`; `R/fdp.R` +
`R/objects.R` call `src/fdp.c` **and nothing else**; `R/fuzz.R` uses
`counters.c` and `protocol_afl.c`; `R/launcher.R`/`replay.R`/`minimize.R` use
`processx` and no native code at all. The companion depends on `zufuzz` and
obtains the counter region through `R_GetCCallable("zufuzz", ...)`, R's
documented cross-package C interface — not through the dynamic linker. It is
the only place `LLVMFuzzerRunDriver` or `src/libfuzzer/` is named, and the
only one that loads its DLL with `library.dynam(local = FALSE)`.

Never patch `src/libfuzzer/` in the companion; it is vendored verbatim (a file
subset) from the LLVM release in `src/libfuzzer/VERSION`. Work around in
`bridge.cpp`, and build against libFuzzer's documented *interface* only —
libFuzzer is in upstream maintenance mode, and interface discipline is what
makes a drop-in replacement a link-time swap.

`draw()` is **not pure R**: R for spec interpretation and object assembly, C
for the byte cursor. The byte→value mapping is implemented once, in
`src/fdp.c`; `draw()` and `fdp$consume_object()` are two front doors onto it.
A second (pure-R) implementation would drift and break "same bytes, same
object". Assembly-in-R vs C is provisional pending Stage 12 benchmarks.

### Structured inputs and object generation

`fuzzed_data_provider()` splits bytes into typed values; `r_object(...)` plus
`fdp$consume_object(spec)` turns the same bytes into R objects so a campaign
can search argument *shape*. The invariant that makes it work: an object is a
pure deterministic function of the bytes — no R RNG, no clock. That is what
lets an engine's mutator edit structure, lets minimization shrink objects, and
lets `draw(spec, n, seed)` generate the same objects **interactively with no
engine installed**. `as_seed()` saves a drawn object's bytes into a corpus;
`object_from()` renders a crash artifact back into the object. Validity levels
`strict`/`nasty` are in 0.1; `adversarial` (objects that lie about their class
or dim) is deferred because a crash there is a hardening note, not
automatically a defect. Prior art is `hedgehog` and `fuzzr`; neither is
byte-driven, which is why neither composes with coverage guidance.

### Out of scope for 0.1.0

Native coverage as a supported feature (track N decides), `sanitizer_build()`,
`install_engine()` (0.1 prints the package-manager command), a LibAFL
backend, comparison tracing on the AFL++ engine, an R custom-mutator
API, regex hooks, S4/R6/RC instrumentation, the `adversarial` validity level,
and any campaign engine on Windows (develop, instrument, replay, minimize and
report coverage natively; run campaigns in WSL).
