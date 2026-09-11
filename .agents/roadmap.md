# zufuzz 0.1.0 implementation roadmap

**Status:** planned, second revision (libFuzzer-embedded design)
**Design:** [design-zufuzz.md](design-zufuzz.md) (native code and sanitizers are §10)
**Release target:** `0.1.0` on GitHub / r-universe (not CRAN)

Each stage leaves the package installable and tested, and does not pull work
forward from later stages. A stage may be one commit or one pull request; it is
not merged while its completion criteria are unmet.

```text
foundation (vendored libFuzzer)
  -> bridge: fuzz() + crash artifacts          -> Gate A
  -> counters + R instrumentation + cmp tracing -> Gate B
  -> FuzzedDataProvider
  -> launcher, replay, minimize
  -> sanitizer configurations + Docker
  -> docs, CI smoke
  -> benchmarks                                -> Gate C
  -> release
Track N (native coverage) runs in parallel after Stage 3.
```

## Working rules

- Complete stages in order unless marked parallel.
- Keep public APIs internal until the stage that documents and exports them.
- Every stage adds deterministic tests. No unit test may depend on the fuzzer
  randomly finding an input; feedback tests use fixed `-seed` and `-runs` and
  fixtures designed to be solved well inside that budget.
- Anything that can kill the process (crash fixtures, hangs, `abort()`) runs
  only in subprocess tests via `fuzz_file()`/`processx`, never in the
  `testthat` process.
- `src/libfuzzer/` is vendored verbatim from a pinned LLVM release recorded in
  `src/libfuzzer/VERSION`; never patch it — work around in the bridge.
- Run `air format .` after changing R code; `devtools::document()` after
  changing roxygen or native registration.
- Record user-facing changes in `NEWS.md` from Stage 1 on.
- A failed gate means revise scope or architecture, not build on top.

## Release scope

0.1.0 delivers: `fuzz()`, `instrument()`, `instrument_package()`,
`instrument_all()`, `instrumentation_report()`, `fuzz(coverage_out =)`,
`fuzzed_data_provider()`, `r_object()`, `draw()`,
`as_seed()`, `object_from()`, `fuzz_file()`,
`fuzz_function()`, `replay()`, `minimize()`, `preload_path()`; R coverage and comparison tracing;
crash/timeout/oom artifacts with JSON sidecars; documented sanitizer
configurations and a Docker image; a CI smoke workflow; benchmarks.

0.1.0 excludes: native coverage as a supported feature, the `adversarial`
validity level, `sanitizer_build()`,
an R custom-mutator API, regex hooks, S4/R6/RC instrumentation, Windows
fuzzing, CRAN.

## Progress tracker

- [ ] Stage 0 — Package foundation with vendored libFuzzer
- [ ] Stage 1 — Bridge: `fuzz()`, artifacts, signals, unwind
- [ ] Stage 2 — Sidecars, fingerprints, per-input controls
- [ ] Gate A — Bridge viable in R
- [ ] Stage 3 — Counter region and native probe routines
- [ ] Stage 4 — Instrumentation planning
- [ ] Stage 5 — Transformation and binding replacement
- [ ] Stage 6 — Comparison tracing
- [ ] Gate B — Trustworthy R feedback
- [ ] Stage 7 — FuzzedDataProvider and R object generation
- [ ] Stage 8 — Launcher and `zufuzz_result`
- [ ] Stage 9 — `replay()`
- [ ] Stage 10 — `minimize()`
- [ ] Stage 11 — Sanitizer configurations, preload, Docker image
- [ ] Stage 12 — Documentation and CI smoke workflow
- [ ] Stage 13 — Benchmarks
- [ ] Gate C — Useful exploration
- [ ] Track N — Native coverage feasibility (parallel, after Stage 3)
- [ ] Stage 14 — 0.1.0 release candidate

## Stage 0 — Package foundation with vendored libFuzzer

**Depends on:** nothing
**Status:** [ ] not started

Work:

- Fill `DESCRIPTION`: title, description, `Authors@R` (including LLVM as `cph`
  for the vendored code), MIT or Apache-2.0 license, `R (>= 4.1)`,
  `SystemRequirements: C++17`, `Imports: processx, jsonlite`, URLs.
- Vendor libFuzzer from a pinned LLVM release into `src/libfuzzer/`; add
  `src/libfuzzer/VERSION`, `LICENSE.note`, `inst/COPYRIGHTS`.
- `Makevars`: compile libFuzzer and a stub bridge on Linux/macOS with
  `CXX_STD = CXX17`; `Makevars.win`: define `ZUFUZZ_NO_LIBFUZZER` and skip it.
- `src/init.c` with routine registration; `.onLoad` loads the DLL with
  `library.dynam(local = FALSE)` and documents why.
- Enforce the layering in design §15 from the first commit: `fdp.c` must not
  include or reference libFuzzer or `bridge.cpp`, and `counters.c` must not
  either. Add a build-time or test-time check (symbol scan) so the value layer
  cannot silently acquire an engine dependency.
- `NEWS.md`, `.Rbuildignore`/`.gitignore` entries for `.zufuzz/`, `fuzz/`,
  `bench/`, `docker/`.
- Confirm `R CMD check` on the CI matrix (ubuntu release/devel/oldrel, macOS,
  Windows) with the expected "compiled code calls abort/exit" NOTE documented.

Complete when the package installs and loads on all CI platforms, an internal
`.Call` confirms `LLVMFuzzerRunDriver` is linked on Linux/macOS and absent on
Windows, and `devtools::document()`/`devtools::test()` are clean.

## Stage 1 — Bridge: `fuzz()`, artifacts, signals, unwind

**Depends on:** Stage 0
**Status:** [ ] not started

The smallest thing that is recognizably Atheris for R: run a closure under
libFuzzer with no coverage.

Work:

- `fuzz(test_one_input, args, ...)`: validate, refuse `interactive()`, build
  argv (defaults from the design, named `...` → `-flag=value`), write the
  re-exec wrapper script (which sets `R_NO_SEGV_HANDLER=1`), set the
  nested-call marker, call the driver. The driver never returns.
- Callback: `RAWSXP` copy, invoke closure under `R_UnwindProtect`/`R_tryCatch`,
  return 0.
- Escaped R error: print `==zufuzz==` header, condition, bounded traceback to
  stderr; flush; `abort()`.
- Reset `SIGSEGV`, `SIGILL`, `SIGBUS`, `SIGINT`, `SIGUSR1`, `SIGUSR2` to
  `SIG_DFL` before the driver starts; record what was replaced.
- Windows: implement only "run listed files once" when `ZUFUZZ_NO_LIBFUZZER`.

Fixtures (subprocess tests, `fuzz/fixtures/`): always-passes; errors on prefix
`"zf"`; C routine that dereferences NULL; R `repeat {}`; C busy loop that never
calls `R_CheckUserInterrupt`; harness that calls `quit()`.

Complete when:

- The error fixture produces `crash-<sha1>` with the exact bytes, an
  `==zufuzz==` diagnostic in stderr, and libFuzzer's error exit code.
- The NULL-dereference fixture and a `SIGILL`/`SIGBUS` fixture (`__builtin_trap()`,
  misaligned access) all produce `crash-<sha1>` — proving R's handlers no longer
  swallow the crash, both with and without the wrapper's `R_NO_SEGV_HANDLER`.
- Both hang fixtures produce `timeout-<sha1>` under `-timeout=2`.
- `SIGINT` to the child stops it cleanly; `-runs=100` exits 0 after libFuzzer's
  final stats, with nothing instrumented and the "no interesting inputs"
  warning visible (the unguided baseline).
- `-fork=1 -ignore_crashes=1 -runs=2000` over the error fixture keeps going
  and produces multiple artifacts, proving re-exec and unwind safety.
- `-jobs=2` and `-minimize_crash=1` re-exec through the wrapper.

Excluded: sidecars, coverage, provider, launcher polish.

## Stage 2 — Sidecars, fingerprints, per-input controls

**Depends on:** Stage 1
**Status:** [ ] not started

Work:

- Sidecar JSON next to the artifact, written before `abort()`, SHA-1 computed
  with the vendored `FuzzerSHA1`; schema per design §8; environment capture
  excludes environment variables.
- Fingerprint for R errors (kind, classes, message, normalized call).
- `ZUFUZZ_EXPECT_FINGERPRINT` gate: mismatching errors return normally.
- `before_each`, `rng_seed` (copy `.Random.seed`), `gc_torture`
  (`gctorture`/`gctorture2`, restored on exit).
- Nested-`fuzz()` detection; interactive-session refusal message.

Complete when a sidecar validates against its schema and names the artifact
that exists on disk; the fingerprint is byte-identical across two processes;
the gate makes a two-error fixture abort only on the expected one; `rng_seed`
makes a `sample()`-dependent fixture deterministic; a PROTECT-bug fixture
crashes under `gc_torture = TRUE` and not without it.

## Gate A — Bridge viable in R

**Depends on:** Stage 2
**Status:** [ ] not passed

Pass when every Stage 1–2 fixture behaves identically on Ubuntu (GCC) and
macOS (Apple clang), with and without `LD_PRELOAD` of an ASan runtime on
Linux, and 10 000 consecutive escaped errors under `-fork=1 -ignore_crashes=1`
leak no memory beyond libFuzzer's own reporting. If the signal or unwind
strategy fails on a platform, that platform is dropped from 0.1 rather than
worked around in user documentation.

## Stage 3 — Counter region and native probe routines

**Depends on:** Stage 0
**Status:** [ ] not started

Work:

- Allocate one `uint8_t` region from a declared site count; register with
  `__sanitizer_cov_8bit_counters_init` and a synthetic `__sanitizer_cov_pcs_init`
  table; refuse re-registration after `fuzz()` starts.
- Probe routine: increment `region[id]`, validating `id` in debug builds only.
- Comparison forwarding routines: memcmp, strcmp, memmem, cmp8 hooks with a
  synthetic `pc` per comparison site.
- On Windows the routines are no-ops.

Complete when libFuzzer prints `Loaded 1 modules (N inline 8-bit counters)`
with the declared N; a fixture that bumps counter k on input byte k reaches
new coverage exactly when expected; a fixture that forwards a fixed string via
the memcmp hook is solved by libFuzzer within a small fixed `-runs`, showing
the hooks are live.

## Stage 4 — Instrumentation planning

**Depends on:** Stage 3
**Status:** [ ] not started

Pure-R planning pass; modifies nothing.

Work:

- Walk function entry, block statements, `if` outcomes, loop-body entry;
  descend per design §5; identify comparison-call sites in `if`/`while`
  conditions and in supported statement positions.
- Dense site IDs from (binding name, AST position) in deterministic order.
- Selection resolution: `pkg::fn`, `pkg:::fn`, local names, package-wide with
  S3 table entries, `exclude`; report primitives, missing bindings, duplicates,
  unsupported constructs.
- `instrument_package(recursive = TRUE)` over `Imports`/`Depends`, and
  `instrument_all(include_base = FALSE)` over loaded namespaces. `zufuzz` is
  excluded unconditionally in both — a test must assert that no zufuzz binding
  is ever selected, since instrumenting the provider or object assembly would
  feed engine execution back as target coverage.
- Manifest digest over instrumentation version, selections, and body digests.

Complete when exact site maps are asserted for empty functions, nested
branches, loops, assignments, quoted code, comparison sites, and unsupported
constructs; the digest is stable across sessions; `instrument_package()` on a
real small CRAN package plans without error and reports its skips;
`instrument_all()` never selects a `zufuzz` binding; `recursive = TRUE`
resolves a dependency graph without cycles or duplicates.

## Stage 5 — Transformation and binding replacement

**Depends on:** Stage 4
**Status:** [ ] not started

Work:

- Rewrite bodies from the plan with probes as `.Call(<NativeSymbolInfo>, id)`.
- Preserve formals, environment, attributes, visibility, invisible `NULL` from
  `if` without `else`, `return`/`break`/`next`, `on.exit`, laziness.
- Replace namespace bindings and S3 table entries, handling locked bindings;
  no-op under `ZUFUZZ_NO_INSTRUMENT=1`.
- `instrumentation_report()` and the startup summary in `fuzz()`.
- `fuzz(coverage_out =)`: dump the accumulated hit set against the site map
  from an `atexit` handler in the bridge (necessary because `fuzz()` never
  returns), in a `covr`-compatible shape.
- JIT: rely on R's recompilation; record `enableJIT` level.

Complete when original/transformed fixtures agree on value, visibility, side
effects, lazy args, errors, and control transfers (including byte-compiled
originals and S3 methods called through the generic); the nested-prefix
fixture is solved by `fuzz()` with fixed `-seed`/`-runs` and not by the
unguided baseline; aliases captured before instrumentation are reported as
uninstrumented; `coverage_out` written after a bounded campaign names exactly
the sites a deterministic fixture reaches, and is produced on the finding and
timeout exit paths too, not only on a clean exit.

## Stage 6 — Comparison tracing

**Depends on:** Stage 5
**Status:** [ ] not started

Work:

- Wrappers for `==`, `!=`, `identical`, `%in%`, `startsWith`, `endsWith`,
  string `switch`, fixed `grepl`/`regexpr` that evaluate the original call and
  forward per design §5.
- Strip wrapper frames from reported tracebacks and fingerprints.
- Bound table forwarding; skip vectorized operands.

Complete when the magic-string fixture (`x == "zufuzz-secret"`), a `%in%`
fixture, a `switch` fixture, and a fixed-`grepl` fixture are each solved with
fixed `-seed`/`-runs` and none is solved by the baseline; an S4 `==` method
fixture still dispatches correctly; fingerprints of instrumented and
uninstrumented runs of the error fixture match.

## Gate B — Trustworthy R feedback

**Depends on:** Stage 6
**Status:** [ ] not passed

Pass when all Stage 4–6 tests pass on Linux and macOS, probe overhead on the
branch-heavy benchmark is measured and published (not necessarily small), and
`instrument_package()` succeeds on three real packages of different styles
(S3-heavy, closure-heavy, thin `.Call` wrapper) with their own test suites
still passing under instrumentation. If semantic differences appear, narrow
the supported subset before continuing.

## Stage 7 — FuzzedDataProvider and R object generation

**Depends on:** Stage 0
**Status:** [ ] not started

Work: `src/fdp.c` cursor and every method from design §11; `R/fdp.R` object;
written consumption spec in the roxygen docs; property tests that consumed
lengths never exceed remaining bytes.

Then the R object generator from the same section: `r_object()` spec,
`$consume_object()`, assembly for `strict` and `nasty` levels (including `NA`
of every type, encoding marks, and both ALTREP and materialized forms), and the
interactive surface `draw()` / `as_seed()` / `object_from()`. `draw(seed =)`
expands through an internal PRNG and must not touch `.Random.seed`. The
`adversarial` level is out of 0.1.

Complete when every method is tested on empty input, one byte, exhausted
state, and boundary ranges; results match the written spec byte for byte on
hand-constructed inputs; `consume_string` never errors on any byte sequence;
integers never produce `NA`; the same bytes yield an `identical()` object in a
fresh session; `draw()` leaves `.Random.seed` untouched; `as_seed()` output
reloads to the same object; `object_from()` on a crash artifact reproduces the
failing object; generation never errors for any byte sequence at `strict` or
`nasty`; `draw()` and `fdp$consume_object()` return `identical()` objects for
the same bytes (one implementation, two front doors — design §15); the whole
provider and generator surface works in a session where `fuzz()` was never
called, and on Windows where libFuzzer is absent.

## Stage 8 — Launcher and `zufuzz_result`

**Depends on:** Gate A
**Status:** [ ] not started

Work: `fuzz_file()` via `processx` with `--vanilla`, env passthrough,
`time_limit`/`runs` mapping, log capture, libFuzzer stats and artifact
parsing, sidecar-from-log for native/timeout/oom findings, `stop_reason`
classification, `print()` method, interrupt handling that kills the child.
Then `fuzz_function()` on top of it: resolve `fn` by namespace name or
serialize it, validate `expect` (reject generic classes), generate the harness
script with the `input` adapter and `instrument_package()` call, run it, and
report the harness path.

Complete when each `stop_reason` is produced by a fixture; interrupting the
launcher leaves no child; results from quiet and verbose runs are identical;
a missing package in the harness is `infrastructure`, not `finding`;
`fuzz_function()` over a fixture package's parser with `expect` set finds a
planted non-expected error and does not report expected rejections; a closure
that references a global helper yields `infrastructure` with a message naming
the missing object; `expect = "error"` is rejected up front.

## Stage 9 — `replay()`

**Depends on:** Stage 8
**Status:** [ ] not started

Work: fresh `Rscript harness input` with `ZUFUZZ_NO_INSTRUMENT=1`;
structured outcome and fingerprint; environment comparison against the
sidecar with mismatch notes; `instrument = TRUE` variant; export and document.

Complete when a deterministic error artifact replays with the same fingerprint;
a normal input reports `normal`; a history-dependent fixture is reported as not
confirmed; version mismatches are reported without blocking.

## Stage 10 — `minimize()`

**Depends on:** Stage 9
**Status:** [ ] not started

Work: drive `-minimize_crash=1 -runs=N -exact_artifact_path=<out>` with the
fingerprint gate; refuse unconfirmed, timeout, and truncated-fingerprint
findings; reconfirm the output via `replay()`; report sizes and status.

Complete when a reducible fixture shrinks and reconfirms; a fixture whose
smaller variants raise a *different* error does not shrink past that point;
the original artifact is byte-identical afterwards; `runs < 3` is rejected.

## Stage 11 — Sanitizer configurations, preload, Docker image

**Depends on:** Gate A
**Status:** [ ] not started

Work (design §10 is the reference for every flag and rationale here):

- Build `zufuzz_preload.so` alongside `zufuzz.so` — libFuzzer plus bridge glue,
  linked with `-fsanitize=address` when a sanitizer configuration is requested —
  so libFuzzer's sancov definitions precede the ASan runtime's in search order.
- `preload_path()` returns it; `fuzz_file(env =)` sets `LD_PRELOAD` for the
  child (`DYLD_INSERT_LIBRARIES` on macOS, expected to hit SIP).
- Document Configuration A (sanitized R build) and Configuration B (stock R
  plus a sanitized target package) with the `ASAN_OPTIONS`/`UBSAN_OPTIONS` from
  design §10. Test whether `use_sigaltstack=0` is still needed once the wrapper
  sets `R_NO_SEGV_HANDLER=1`.
- `docker/Dockerfile` on `rocker/r-devel-ubsan-clang` carrying zufuzz, the
  preload object, and the native fixture package.
- Sidecars derived from sanitizer logs: `kind`, the `SUMMARY:` line, top
  non-R frames, exit code/signal, and the options in effect.
- Startup check on libFuzzer's `Loaded N modules (M inline 8-bit counters)`:
  warn when a sanitized configuration was requested but M equals the R site
  count, meaning no native counters appeared.

Complete when, in the Docker image, a heap-overflow fixture built with
`-fsanitize=address` yields a `crash-` artifact whose replay reproduces the
same `SUMMARY:` line under both configurations; the same run on stock R
without preload is reported as unsanitized rather than silently passing; a
bare signal with no sanitizer report is recorded but not fingerprinted, and
`minimize()` refuses it.

## Stage 12 — Documentation and CI smoke workflow

**Depends on:** Stages 7–11
**Status:** [ ] not started

Work: reference docs for every export; README with the JSON-style harness,
the `Rscript` invocation, replay and minimize; a getting-started vignette
covering expected rejection, instrumentation scope and its holes,
reproducibility levels, and sanitizer setup; `_pkgdown.yml`; a
`fuzz-smoke.yaml` workflow that runs `fuzz_file()` with fixed `-runs`/`-seed`
on the toy harness and uploads `.zufuzz/` on failure.

Complete when `pkgdown::check_pkgdown()` passes, README and vignette run from a
clean install, and `R CMD check` does not start a campaign.

## Stage 13 — Benchmarks

**Depends on:** Stage 12
**Status:** [ ] not started

Work per design §14: `bench/` harnesses (empty, branch-heavy R, thin `.Call`,
one real package); probe, provider, and bridge overhead measured separately;
guided vs unguided with ≥ 30 predeclared seeds, equal `-runs` and equal
`-max_total_time`; sustained-run RSS; publish configuration, raw results, and
the analysis script.

Complete when results reproduce from repository scripts.

## Gate C — Useful exploration

**Depends on:** Stage 13
**Status:** [ ] not passed

Pass when guided search shows a wall-time advantage on branch-heavy R code and
discovers meaningful coverage beyond wrapper entry in the real package
harness. If it fails, profile probe and bridge cost before touching mutation
or scheduling — those belong to libFuzzer.

## Track N — Native coverage feasibility

**Can start after:** Stage 3 · **Blocks 0.1.0:** no
**Status:** [ ] not started

Run this inside the Docker image, on a fixture package: a `.Call` wrapper over
C code with several branches and one deliberate heap overflow behind a 4-byte
magic prefix.

1. Build the fixture with `-fsanitize=address,fuzzer-no-link`.
2. Run under Configurations A and B with the preload; assert M exceeds the R
   site count (design §10 — otherwise the callbacks bound to ASan's
   definitions and there is no native feedback).
3. Show that R-level counters stay constant while native features grow; solve
   the magic prefix through native `trace-cmp`; confirm the overflow yields a
   `crash-` artifact whose bytes replay to the same `SUMMARY:` line.
4. Record toolchain requirements (Clang version, `compiler-rt` availability),
   what happens with GCC-built targets (GCC's `-fsanitize-coverage` support is
   partial), and whether Apple clang can be made to work.
5. Decide: support native coverage as a documented feature in 0.2, or restrict
   it to the Docker image.

Native coverage identities come from libFuzzer's module tables; zufuzz does not
try to make them stable across builds. Deliver reproducible commands, the
counter-count evidence, the crash replay, the toolchain constraints, and a
written decision for 0.2. No experimental code becomes a package dependency.

## Stage 14 — 0.1.0 release candidate

**Depends on:** Gate C; Stages 0–13
**Status:** [ ] not started

Work: review every export, condition class, result field, sidecar schema, and
documented limitation against the implementation; freeze instrumentation and
provider algorithm versions; run the full CI matrix, the Docker image tests,
and the benchmarks; confirm generated data is build-ignored; set
`Version: 0.1.0`, finalize `NEWS.md`, tag.

Complete when Gates A, B, C are recorded as passed, `R CMD check` has no
errors or warnings and only the documented NOTE, and the package claims
nothing deferred.

## 0.1.0 definition of done

A developer can:

1. Write `test_one_input` in a script, call `instrument_package()` and
   `fuzz()`, and run it with `Rscript harness.R corpus/ -max_len=… -dict=…`.
2. Consume structured values through `fuzzed_data_provider()`, and fuzz
   functions that take R objects via `r_object()`.
3. Draw those same objects interactively with `draw()`, keep interesting ones
   as corpus seeds with `as_seed()`, and render a crash artifact back into the
   object that caused it with `object_from()`.
4. Get `crash-`/`timeout-`/`oom-` artifacts with sidecars for R errors,
   native crashes, R and native hangs, and memory blow-ups.
5. Watch libFuzzer solve prefix and magic-string checks in instrumented R code.
6. Run the same harness under a sanitized R build or a preloaded sanitizer and
   get native findings as artifacts.
7. `replay()` an artifact in a fresh process and `minimize()` a confirmed
   R-error finding without changing its fingerprint.
8. Use `fuzz_file()` in CI and distinguish budget, finding, interrupted, and
   infrastructure outcomes.

Each is covered by deterministic automated tests.
