# zufuzz 0.1.0 implementation roadmap

**Status:** planned, third revision (CRAN package + companion engine package)
**Design:** [design-zufuzz.md](design-zufuzz.md) (packaging is §13, layering §15,
execution models §4, sanitizers §10)
**Release target:** `zufuzz 0.1.0` on **CRAN**; `zufuzz.libfuzzer 0.1.0` on
r-universe

Each stage leaves the package installable and tested, and does not pull work
forward from later stages. A stage may be one commit or one pull request; it is
not merged while its completion criteria are unmet.

Two packages, two tracks. The CRAN core does not wait for the companion;
Gate A now gates the companion only.

```text
zufuzz (CRAN)                                   zufuzz.libfuzzer (r-universe)
  0  foundation, CRAN-shaped                       E0  vendored libFuzzer, GCC + Apple clang
  1  counter region + sink modes        ---------> E1  bridge: driver, unwind, signals, abort
  2  instrumentation planning                      E2  in-process sidecars, gate, controls
  3  transformation, coverage_out                       Gate A — bridge viable in R
  4  fuzz() run-once, sidecars, replay()           E3  preload object, Configuration B
  5  launcher, engines(), fuzz_function()          Track N — native coverage (Docker)
  6  AFL++ worker protocol
  7  minimize()
  8  provider + object generation   (parallel, after 0)
       Gate B — trustworthy R feedback  (needs an engine: AFL++ on CI, companion on CI)
  9  comparison tracing (companion engine)
 10  sanitizer configurations, Docker image
 11  docs, CRAN preparation, CI smoke
 12  benchmarks
       Gate C — useful exploration
 13  0.1.0 release: CRAN submission + companion tag
```

## Working rules

- Complete stages in order unless marked parallel.
- Keep public APIs internal until the stage that documents and exports them.
- Every stage adds deterministic tests. No unit test may depend on the fuzzer
  randomly finding an input; feedback tests use fixed `-seed` and `-runs` (or
  AFL's `-s` and `-E`) and fixtures designed to be solved well inside that
  budget.
- Anything that can kill the process (crash fixtures, hangs, `pskill`,
  `abort()`) runs only in subprocess tests via `fuzz_file()`/`processx`, never
  in the `testthat` process.
- **`zufuzz.so` never calls `exit`, `abort`, `_exit`, or writes to stdio.**
  The Stage 0 symbol scan is a test; it is a CRAN gate as well as a layering
  gate.
- Every engine-dependent test is `skip_if_not(engine_available(...))`. CI
  installs AFL++ on one Ubuntu job and the companion on Ubuntu and macOS; the
  Windows job and one Ubuntu job run with no engine at all, and that is the
  configuration `R CMD check --as-cran` is judged on.
- `src/libfuzzer/` in the companion is vendored verbatim from a pinned LLVM
  release recorded in `src/libfuzzer/VERSION`; never patch it — work around
  in the bridge. The companion builds against libFuzzer's documented
  interface only.
- Run `air format .` after changing R code; `devtools::document()` after
  changing roxygen or native registration.
- Record user-facing changes in `NEWS.md` from Stage 1 on.
- A failed gate means revise scope or architecture, not build on top.

## Release scope

`zufuzz 0.1.0` delivers: `fuzz(engine =)`, `instrument()`,
`instrument_package()`, `instrument_all()`, `instrumentation_report()`,
`coverage_out`, `fuzzed_data_provider()`, `r_object()`, `draw()`,
`as_seed()`, `object_from()`, `engines()`, `engine_available()`,
`fuzz_file()`, `fuzz_function()`, `replay()`, `minimize()`; R coverage
feedback on two engines; the AFL++ child protocol; crash/timeout/oom
artifacts with JSON sidecars on every engine; documented sanitizer
configurations and a Docker image; a CI smoke workflow; benchmarks; a clean
`R CMD check --as-cran` on Linux, macOS, and Windows.

`zufuzz.libfuzzer 0.1.0` delivers: the in-process libFuzzer engine for Linux
and macOS with comparison tracing, `-fork`/`-jobs`/`-minimize_crash` through
the re-exec wrapper, and `preload_path()`.

0.1.0 excludes: native coverage as a supported feature, the `adversarial`
validity level, `sanitizer_build()`, `install_engine()`, a LibAFL backend,
comparison tracing on AFL++, an R custom-mutator API, regex hooks,
S4/R6/RC instrumentation, and any campaign engine on Windows.

## Progress tracker

- [x] Stage 0 — Package foundation, CRAN-shaped
- [x] Stage 1 — Counter region and sink modes
- [x] Stage 2 — Instrumentation planning
- [x] Stage 3 — Transformation, binding replacement, `coverage_out`
- [x] Stage 4 — `fuzz()` run-once mode, sidecars, fingerprints, `replay()`
- [x] Stage 5 — Launcher, `engines()`, `zufuzz_result`, `fuzz_function()`
- [x] Stage 6 — AFL++ worker protocol
- [x] Stage 7 — `minimize()`
- [x] Stage 8 — FuzzedDataProvider and R object generation (parallel, after Stage 0)
- [ ] Gate B — Trustworthy R feedback
- [ ] Stage 9 — Comparison tracing (companion engine)
- [ ] Stage 10 — Sanitizer configurations and Docker image
- [ ] Stage 11 — Documentation, CRAN preparation, CI smoke workflow
- [ ] Stage 12 — Benchmarks
- [ ] Gate C — Useful exploration
- [ ] Stage 13 — 0.1.0 release
- [ ] Companion E0 — Foundation with vendored libFuzzer
- [ ] Companion E1 — Bridge: driver, artifacts, signals, unwind
- [ ] Companion E2 — In-process sidecars, fingerprint gate, per-input controls
- [ ] Gate A — Bridge viable in R
- [ ] Companion E3 — Preload object and Configuration B
- [ ] Track N — Native coverage feasibility (parallel, after E1)

## Stage 0 — Package foundation, CRAN-shaped

**Depends on:** nothing
**Status:** [x] done — all seven checks green on CI

Work:

- Fill `DESCRIPTION`: title, description, `Authors@R`, MIT license,
  `R (>= 4.1)`, `SystemRequirements: AFL++ (optional, for engine = "afl")`,
  URLs. No `OS_type`.
  **A dependency is declared by the stage that first uses it, not here** —
  `R CMD check` NOTEs an unused `Imports`, and Stage 0 has no R code at all.
  So `digest` arrived with the manifest digest in Stage 2, `jsonlite` arrives
  with the sidecars in Stage 4, `processx` with the launcher in Stage 5, and `Suggests: zufuzz.libfuzzer` plus
  `Additional_repositories:` only once the companion exists and is
  installable (Stage 11) — declaring a Suggests on a package that does not
  yet exist is an immediate check NOTE.
- `src/`: `init.c` with routine registration (`R_useDynamicSymbols(FALSE)`,
  `R_forceSymbols(TRUE)`); stubs for `counters.c`, `protocol_afl.c`,
  `fdp.c`; a shared `zufuzz.h` carrying the platform guard. One `Makevars`
  for every platform; `protocol_afl.c` compiles to no-ops where System V
  shared memory is absent, with an internal `.Call` reporting which.
  No C++, no `Makevars.win`, no `configure`.
  The companion reaches the counter region through `R_RegisterCCallable()` /
  `R_GetCCallable()` (Stage 1), **not** through `library.dynam(local =
  FALSE)`: the second revision needed `RTLD_GLOBAL` because the engine lived
  in this DLL, and that reason left with the engine.
- **Symbol scan test**: after build, `nm` (or `dumpbin` on Windows) over
  `zufuzz.so` asserts no reference to `exit`, `_exit`, `abort`, `printf`,
  `puts`, `fprintf`, `fputs`, `fwrite`, `write`, or any `__sanitizer_*`
  symbol. This enforces design §15's layering and CRAN's compiled-code rule
  at once, from the first commit.
- `NEWS.md`, `.Rbuildignore`/`.gitignore` entries for `.zufuzz/`, `fuzz/`,
  `bench/`, `docker/`, `cran-comments.md`.
- CI: `R CMD check --as-cran` on ubuntu release/devel/oldrel, macOS, Windows,
  all with no engine installed.
  **Amended at Stage 3:** the gate was `error-on: '"note"'`, which stopped
  working once `unlockBinding` entered the package — that NOTE is inherent to
  replacing a binding in a locked namespace, and the alternatives were hiding
  the call from the reviewer or never adding an expected note again. CI now
  gates on `"warning"`, and the architectural invariant is enforced by
  `tests/testthat/test-symbols.R` directly, which is the more precise gate:
  a failing test fails the check.

Complete when the package installs and loads on all CI platforms, the symbol
scan passes on all of them, `R CMD check --as-cran` reports no compiled-code
NOTE anywhere, and `devtools::document()`/`devtools::test()` are clean.

Status: **done**. All seven checks green on the first CI run — macOS,
Windows, and Ubuntu release/devel/oldrel-1 — each `Status: OK` with
`checking compiled code ... OK`, under `error-on: '"note"'`.

One qualification worth carrying forward: the symbol scan **runs** on Linux
and macOS and **skips** on Windows (`SKIP 2 | PASS 6`), because Rtools puts no
`nm` on the PATH and a PE DLL has no undefined-symbol table to read. Windows
is covered by R's own "checking compiled code" step instead. So the layering
rule is machine-enforced on two platforms of three, and if a future stage
needs it enforced on Windows the tool to reach for is `objdump -p` over the
import table, not `nm`. The scan was verified to fail on an injected
`exit()`/`fprintf()` rather than assumed to work.

## Stage 1 — Counter region and sink modes

**Depends on:** Stage 0
**Status:** [x] done

Work:

- Allocate one `uint8_t` region from a declared site count; refuse resizing
  after a campaign starts.
- Probe routine with three sink modes, fixed at attach time: `none`
  (`region[id]++`), `afl` (`map[id ^ prev]++; prev = id >> 1` into an
  externally supplied 64 KiB map), `libfuzzer` (`region[id]++`, region
  registered by the companion). `id` validated in debug builds only.
- Exported C accessor `zufuzz_counter_region(&start, &end)` and an R-level
  `.zufuzz_attach_sink(mode, map_ptr)` for engines. `counters.c` references
  no `__sanitizer_*` symbol in any mode; the symbol scan keeps it that way.
- Comparison forwarding routines are declared here with a `none`/`afl`
  no-op body; their `libfuzzer` bodies live in the companion (Stage 9).
- On Windows everything compiles and `none` mode is fully functional.

Complete when a fixture that bumps counter *k* on input byte *k* reads back
the expected region in `none` mode on all platforms; the `afl` mode writes the
expected edge for a known `(prev, id)` sequence into a caller-supplied buffer;
a fake companion (a test-only shared object) can obtain `(start, end)` through
the accessor; and the symbol scan still passes.

Two things settled during implementation, both worth not rediscovering:

- **Counters wrap at 256; they do not saturate.** An inline 8-bit counter is
  `*p += 1` in sancov and `map[loc]++` in AFL, and both engines bucket the
  result, so a site hit exactly 256 times reads as never hit. Saturating
  would be friendlier but would make zufuzz's counters mean something
  different from the native ones libFuzzer sees in the same process. The
  test asserts the wrap so nobody "fixes" it later.
- **The fake companion is not a second shared object.** Building one inside
  `R CMD check` is not worth the portability cost. Instead an internal
  `.Call` resolves the accessor through
  `R_GetCCallable("zufuzz", "zufuzz_counter_region")` — the exact path the
  companion uses — and reports the region it sees. That exercises the
  registration, which is the part that can break.

## Stage 2 — Instrumentation planning

**Depends on:** Stage 1
**Status:** [x] done

Pure-R planning pass; modifies nothing.

Work:

- Walk function entry, block statements, `if` outcomes, loop-body entry;
  descend per design §5; identify comparison-call sites in `if`/`while`
  conditions and in supported statement positions.
- Dense site IDs from (binding name, AST position) in deterministic order.
  Dense ids are also what makes the AFL edge map collision-free below 64 K
  sites.
- Selection resolution: `pkg::fn`, `pkg:::fn`, local names, package-wide with
  S3 table entries, `exclude`; report primitives, missing bindings, duplicates,
  unsupported constructs.
- `instrument_package(recursive = TRUE)` over `Imports`/`Depends`, and
  `instrument_all(include_base = FALSE)` over loaded namespaces. `zufuzz` is
  excluded unconditionally in both — a test must assert that no zufuzz binding
  is ever selected, since instrumenting the provider or the worker loop would
  feed engine execution back as target coverage.
- Manifest digest over instrumentation version, selections, and body digests.

Complete when exact site maps are asserted for empty functions, nested
branches, loops, assignments, quoted code, comparison sites, and unsupported
constructs; the digest is stable across sessions; `instrument_package()` on a
real small CRAN package plans without error and reports its skips;
`instrument_all()` never selects a `zufuzz` binding; `recursive = TRUE`
resolves a dependency graph without cycles or duplicates.

Settled during implementation:

- **A site's address is a path string**, `"2.3"` meaning `body[[2]][[3]]`,
  `""` the body itself. Stage 3 converts it back with `path_indices()`. A
  string is what makes an expected site map readable in a test, and asserting
  the whole map rather than a count is the point: a rule that moves a probe
  one node is a different instrumentation, and the digest says so.
- **Nested function literals are reported, not instrumented.** Rewriting
  inside one would change what `substitute()` sees of the argument it is
  usually passed as. But the walk still *reads* call arguments looking for
  them, so a closure-heavy package gets thin coverage it can explain rather
  than thin coverage it cannot. This is the Gate B "closure-heavy" case, and
  the report is what will make it diagnosable.
- **A comparison is a site only when it can be decided statically.** `switch`
  qualifies in its string form, `grepl`/`regexpr` only with a literal
  `fixed = TRUE`. A false negative costs some feedback; a false positive
  would rewrite a call that means something else.

## Stage 3 — Transformation, binding replacement, `coverage_out`

**Depends on:** Stage 2
**Status:** [x] done

Work:

- Rewrite bodies from the plan with probes as `.Call(<NativeSymbolInfo>, id)`.
- Preserve formals, environment, attributes, visibility, invisible `NULL` from
  `if` without `else`, `return`/`break`/`next`, `on.exit`, laziness.
- Replace namespace bindings and S3 table entries, handling locked bindings;
  no-op under `ZUFUZZ_NO_INSTRUMENT=1`.
- `instrumentation_report()` and the startup summary.
- `coverage_out` as a run-once feature: run a set of inputs in `none` mode and
  write the hit set against the site map in a `covr`-compatible shape. This
  is engine-free and runs inside `R CMD check`.
- JIT: rely on R's recompilation; record `enableJIT` level.

Complete when original/transformed fixtures agree on value, visibility, side
effects, lazy args, errors, and control transfers (including byte-compiled
originals and S3 methods called through the generic); aliases captured before
instrumentation are reported as uninstrumented; `coverage_out` over a fixed
corpus names exactly the sites a deterministic fixture reaches, on all three
platforms.

Found by building it, and worth not rediscovering:

- **Never rebuild an assignment with `out[[3L]] <- rhs`.** Assigning `NULL`
  into a call *removes* that element, so `x <- NULL` silently becomes a
  one-argument `` `<-`(x) `` that deparses identically and fails only when
  evaluated. `x <- NULL` is ordinary R; the bug surfaced on
  `testthat:::o_apply`, whose first line it is. Calls are rebuilt with
  `as.call(list(...))`, which keeps a `NULL` element as an element, and there
  is a regression test asserting arity rather than deparse.
- **The planner/transformer cross-check earns its keep.** `transform_function()`
  compares the sites it emitted against the plan's and refuses if they differ.
  It caught a wiring bug immediately — sites read from `out$sites` instead of
  `out$st$sites` — that would otherwise have produced a site map describing
  coverage the target never had.
- **The undo record is written per binding, not at the end.** A failure
  part-way through a package must still be reversible; assembling the record
  and storing it after the loop leaves the session permanently
  half-instrumented.
- **`instrument_all()` is not applied inside the test process.** It would
  rewrite testthat, rlang and pkgload while they are on the call stack. The
  criterion is about what is *selected*, so that is what the test asserts.

## Stage 4 — `fuzz()` run-once mode, sidecars, fingerprints, `replay()`

**Depends on:** Stage 3
**Status:** [x] done

Work:

- `fuzz(test_one_input, engine =)`: validate; resolve the engine per design
  §3; refuse campaigns when `interactive()`; run-once mode over positional
  files and directories with `before_each`, `rng_seed`, `gc_torture`
  (restored on exit), and `coverage_out`. Run-once never kills the process.
- Escaped-error handling shared by every mode: `==zufuzz==` diagnostic,
  bounded traceback, fingerprint (kind, classes, message, normalized call),
  sidecar JSON per design §8 with SHA-1 names from `digest`, artifact copy of
  the input. `ZUFUZZ_EXPECT_FINGERPRINT` gate: mismatching errors are treated
  as normal.
- Nested-`fuzz()` detection; interactive refusal message.
- `replay(path, input)`: `Rscript path input` in a fresh process with
  `ZUFUZZ_NO_INSTRUMENT=1` — run-once mode, no engine — with structured
  outcome, fingerprint, and environment comparison against the sidecar;
  `instrument = TRUE` variant.

Complete when a sidecar validates against its schema and names the artifact
that exists on disk; the fingerprint is byte-identical across two processes;
the gate makes a two-error fixture record only the expected one; `rng_seed`
makes a `sample()`-dependent fixture deterministic; a PROTECT-bug fixture
crashes under `gc_torture = TRUE` and not without it (subprocess test); a
deterministic error artifact replays with the same fingerprint; a normal input
reports `normal`; a history-dependent fixture is reported as not confirmed;
all of it on Windows too.

Settled, and one criterion deliberately deferred:

- **A fingerprint must not depend on the input.** The originating call usually
  carries the offending value, so keeping it verbatim would make every input
  its own finding and nothing would ever match anything -- no confirmation, no
  gated minimization. The call is normalised to `function/arity`
  (`parse(text = x)` becomes `parse/1`). It does still distinguish the same
  `stop()` raised from different functions, which is correct and caught a test
  of mine that assumed otherwise.
- **A traceback starts at the target.** `sys.calls()` in the handler returns
  the whole stack, so twenty frames of testthat or an IDE would bury the one
  frame that matters. `invoke_target()` records the stack depth on entry and
  drops everything above it.
- **`processx` arrives here, not at Stage 5.** `replay()` needs a genuinely
  fresh process; that is its first use.
- **`ZUFUZZ_ARTIFACT_DIR`** lets a parent process decide where a harness
  writes its findings, without the harness script knowing. `replay()` uses it
  to read the child's sidecar rather than parsing the child's stderr -- a
  harness may print anything, but a sidecar has a schema.
- **Subprocess tests need an installed zufuzz.** They skip under
  `devtools::test()` (pkgload's copy is invisible to a child) and run under
  `R CMD check`, which is what CI gates on. A local `devtools::check()` is
  therefore the only way to exercise them.
- **Deferred: the PROTECT-bug fixture.** Proving `gc_torture = TRUE` makes a
  missing `PROTECT` crash needs deliberately memory-unsafe native code, which
  must not ship in the CRAN package. What zufuzz owns -- enabling torture
  around the call and restoring it afterwards, including on error -- is tested
  here; the crash itself moves to Stage 10, where the Docker image already
  carries native fixtures that misbehave on purpose.

## Stage 5 — Launcher, `engines()`, `zufuzz_result`, `fuzz_function()`

**Depends on:** Stage 4
**Status:** [x] done

Work:

- `engines()` / `engine_available()`: the search order from design §3
  (option, env var, companion namespace, `Sys.which`), what was found where,
  and the install hint for what was not. On Windows: reports no campaign
  engine and points at WSL.
- `fuzz_file()` via `processx` with `--vanilla`, `R_NO_SEGV_HANDLER=1`, env
  passthrough, `time_limit`/`runs` mapping per engine, log capture,
  **artifact-directory classification** with the exit code as corroboration,
  sidecar-from-log for native/timeout/oom findings, `stop_reason`, `print()`
  method, interrupt handling that kills the child, `coverage = TRUE` running
  `coverage_out` over the final corpus.
- `tests/fixtures/fake-engine.R`: a supervisor test double that writes
  artifacts and exit codes on cue, so every `stop_reason` is exercised inside
  `R CMD check` with no engine.
- `fuzz_function()`: resolve `fn` by namespace name or serialize it, validate
  `expect` (reject generic classes), generate the harness with the `input`
  adapter and `instrument_package()` call, run through `fuzz_file()`, report
  the harness path.

Complete when each `stop_reason` is produced by the fake engine; interrupting
the launcher leaves no child; results from quiet and verbose runs are
identical; a missing package in the harness is `infrastructure`, not
`finding`; running on a machine with no engine is `infrastructure` with a
message naming `engines()`; `fuzz_function()` over a fixture package's parser
with `expect` set finds a planted non-expected error under the fake engine; a
closure that references a global helper yields `infrastructure` naming the
missing object; `expect = "error"` is rejected up front.

## Stage 6 — AFL++ worker protocol

**Depends on:** Stage 5
**Status:** [x] done — verified green by the afl-engine CI job

Modelled on python-afl's `afl.pyx` (235 lines) and its 22-line launcher.

Work:

- `protocol_afl.c`: `shmat` of `__AFL_SHM_ID`; fork server on fds 198/199
  (hello, go, fork, pid, wait, status); `next_input` reading stdin or the `@@`
  file; persistent-mode counter. Leaf routines; nothing evaluates R.
- `fuzz()` under `engine = "afl"` (or `auto` with `__AFL_SHM_ID` set):
  attach after instrumentation, switch the sink to `afl`, then the R-level
  `repeat` loop from design §4. Escaped error → sidecar → `tools::pskill(SIGABRT)`.
- `fuzz_file(engine = "afl")`: `afl-fuzz -i -o -t -x -m … -- Rscript --vanilla
  harness.R`, `AFL_SKIP_BIN_CHECK=1`, `-V`/`-E` for `time_limit`/`runs`,
  `-M`/`-S` for `jobs`; import `crashes/`/`hangs/` into `.zufuzz/artifacts/`
  under `crash-`/`timeout-` names; AFL's directory kept verbatim.
- `afl-cmin` and `afl-tmin` thin wrappers (used by Stage 7).
- CI: one Ubuntu job installs `afl++` from apt; all AFL tests are
  `skip_if_not(engine_available("afl"))`.

Fixtures (subprocess, `fuzz/fixtures/`): always-passes; errors on prefix
`"zf"`; C routine that dereferences NULL; R `repeat {}`; C busy loop that
never calls `R_CheckUserInterrupt`.

Complete when, under `afl-fuzz` on the Ubuntu job: the error fixture yields an
imported `crash-<sha1>` with the exact bytes and a sidecar written by the
child; the NULL-dereference fixture yields a crash (proving `R_NO_SEGV_HANDLER`
and `pskill` both reach the supervisor); both hang fixtures yield `hangs/`
entries imported as `timeout-`; the nested-prefix fixture is solved with a
fixed `-s` seed inside a fixed `-E` budget and not by an all-zero bitmap in
that budget; `-M/-S` runs two workers; the fork server survives a harness that
loads three packages before `fuzz()`; the persistent loop runs 10 000 inputs
without growth in RSS beyond the supervisor's own reporting.

Scope and verification, decided here:

- **Deferred fork server, no persistent mode.** Persistent mode saves one
  `fork()` per input but doubles the protocol state machine, and for an R
  target the fork is not the expensive part -- R startup is, and the deferred
  server already pays that once. Stage 12's benchmarks are what should decide
  whether it earns the complexity, not a guess now.
- **The shm attach handles both flavours.** `__AFL_SHM_ID` carries a System V
  segment id on most Linux builds and a POSIX shared-memory *name* on builds
  compiled with `USEMMAP`, which is the default on macOS. Trying the integer
  form and falling back to `shm_open()` is how one binary copes with both.
- **`SIGABRT`, written as 6.** `tools` exports SIGKILL and SIGTERM but not
  SIGABRT. The choice matters: SIGKILL is what AFL sends a child that overran
  its timeout, so a self-inflicted SIGKILL would be filed as a hang; SIGUSR1
  (python-afl's default) hits R's own handler, which saves a workspace and
  exits cleanly, which AFL reads as "this input was fine". R installs no
  SIGABRT handler and AFL counts any signal death as a crash.
- **`engine = "afl"` with no supervisor is an error, not a silent no-op.**
  Without `__AFL_SHM_ID` the handshake fails on its first write and the
  harness would return having done nothing -- a harness that appears to work
  and tests nothing.
- **The campaign test must not depend on the fuzzer getting lucky.** The
  first version seeded `"aa"` and asked AFL to find a nested `"zf"` prefix in
  45 seconds. It passed once and failed once -- a stochastic test, which the
  working rules above forbid, because a red build then means nothing. AFL++
  also skips its deterministic mutation stage by default, so "reachable by a
  byte increment" is not the guarantee it appears to be. The test now seeds
  one byte from the crash with AFL's RNG fixed, and asserts what it is
  actually for: the worker speaks the protocol, a crash is detected as a
  crash, and the artifact is imported with a sidecar. Whether guided search
  beats unguided is Gate C's question, measured over many seeds in Stage 12.
- **This stage cannot be verified on a developer machine without AFL++.** The
  tests split: command-line construction, flag mapping, artifact import,
  attach failure and handshake refusal run everywhere; the campaign tests are
  `skip_if_not(engine_available("afl"))` and execute only in the new
  `afl-engine` CI job. A protocol cannot be verified against a mock of
  itself.

## Stage 7 — `minimize()`

**Depends on:** Stage 6
**Status:** [x] done

Work: the gated R-side reducer (delta debugging over bytes, each candidate
confirmed by `replay()` with `ZUFUZZ_EXPECT_FINGERPRINT`); refuse unconfirmed,
timeout, and truncated-fingerprint findings; `accelerate = TRUE` runs
`afl-tmin` first when AFL++ is available (and `-minimize_crash=1` once the
companion exists), then finishes with the gated reducer; reconfirm the output;
report sizes and status.

Complete when a reducible fixture shrinks and reconfirms with no engine, on
Windows; a fixture whose smaller variants raise a *different* error does not
shrink past that point; the original artifact is byte-identical afterwards;
`runs < 3` is rejected; the accelerated path yields a result the gated
reducer accepts unchanged.

Settled here:

- **The accelerator runs *under* the gate, not beside it.** `afl-tmin` only
  knows "did the child die", so left alone it will walk from the bug being
  minimized into a smaller different one and report success.
  `ZUFUZZ_EXPECT_FINGERPRINT` makes the child treat any other error as a
  normal run, and whatever `afl-tmin` produces is then re-checked and
  finished by the R reducer. A wrong answer from the accelerator costs time,
  never correctness.
- **`runs` is a process budget, not an iteration count.** Every candidate is
  a fresh `Rscript`, so the budget is the only real cost control; it is
  decremented by the confirmation and reconfirmation runs too, because those
  are processes as well.
- **Refusals are results, not errors.** No sidecar, no fingerprint, a
  timeout, or a finding that no longer reproduces each come back as a
  `zufuzz_minimize` carrying the reason. Minimizing any of them would produce
  a confident answer about nothing.

## Stage 8 — FuzzedDataProvider and R object generation

**Depends on:** Stage 0 · **parallel** with Stages 1–7
**Status:** [x] done

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
surface works with no engine installed and on Windows.

## Gate B — Trustworthy R feedback

**Depends on:** Stages 6, 8; companion E1
**Status:** [ ] not passed

Pass when all Stage 2–6 tests pass on Linux and macOS under **both** engines
(AFL++ on the Ubuntu job; the companion on Ubuntu and macOS); the
nested-prefix fixture is solved by each engine with fixed seed and budget and
by neither unguided baseline; probe overhead on the branch-heavy benchmark is
measured and published (not necessarily small); and `instrument_package()`
succeeds on three real packages of different styles (S3-heavy, closure-heavy,
thin `.Call` wrapper) with their own test suites still passing under
instrumentation. If semantic differences appear, narrow the supported subset
before continuing.

## Stage 9 — Comparison tracing (companion engine)

**Depends on:** Gate B; companion E2
**Status:** [ ] not started

Work (in `zufuzz`, the rewrite; in the companion, the forwarding):

- Wrappers for `==`, `!=`, `identical`, `%in%`, `startsWith`, `endsWith`,
  string `switch`, fixed `grepl`/`regexpr` that evaluate the original call
  and forward per design §5 through the routines declared in Stage 1. The
  companion supplies the `libfuzzer` bodies (`__sanitizer_weak_hook_memcmp`
  etc., synthetic `pc` per site); `none`/`afl` bodies stay no-ops in 0.1.
- Strip wrapper frames from reported tracebacks and fingerprints.
- Bound table forwarding; skip vectorized operands.

Complete when the magic-string fixture (`x == "zufuzz-secret"`), a `%in%`
fixture, a `switch` fixture, and a fixed-`grepl` fixture are each solved under
the companion with fixed `-seed`/`-runs` and none is solved by the baseline;
an S4 `==` method fixture still dispatches correctly on every engine;
fingerprints of instrumented and uninstrumented runs of the error fixture
match; and the same wrappers under `afl` are measured as pure overhead with no
semantic change.

## Stage 10 — Sanitizer configurations and Docker image

**Depends on:** Stage 6; companion E3 for the preload part
**Status:** [ ] not started

Work (design §10 is the reference):

- **Worker path first**: document and test running `afl-fuzz` over a
  sanitized R build (`rocker/r-devel-san`, `rocker/r-devel-ubsan-clang`)
  with the `ASAN_OPTIONS`/`UBSAN_OPTIONS` from §10 — no preload, no
  companion. This is the recommended sanitized configuration.
- `docker/Dockerfile` on `rocker/r-devel-ubsan-clang` carrying zufuzz, AFL++,
  the companion and its preload object, and the native fixture package.
- Sidecars derived from sanitizer logs: `kind`, the `SUMMARY:` line, top
  non-R frames, exit code/signal, options in effect — on both engines.
- Companion path: Configuration B with `preload_path()` and the startup
  check on libFuzzer's `Loaded N modules (M inline 8-bit counters)` line;
  test whether `use_sigaltstack=0` is still needed under `R_NO_SEGV_HANDLER=1`.

Complete when, in the Docker image, a heap-overflow fixture built with
`-fsanitize=address` yields a `crash-` artifact whose replay reproduces the
same `SUMMARY:` line under the worker path and under both companion
configurations; the same run on stock R is reported as unsanitized rather
than silently passing; a bare signal with no sanitizer report is recorded but
not fingerprinted, and `minimize()` refuses it.

## Stage 11 — Documentation, CRAN preparation, CI smoke workflow

**Depends on:** Stages 7–10
**Status:** [ ] not started

Work: reference docs for every export; README with the harness, the three
ways to run it (`Rscript` under the companion, `afl-fuzz`, `fuzz_file()`),
`engines()`, replay and minimize; a getting-started vignette covering expected
rejection, instrumentation scope and its holes, reproducibility levels,
choosing an engine, and sanitizer setup; a "Windows" section that says
exactly what works and what needs WSL; `_pkgdown.yml`; `cran-comments.md`;
`fuzz-smoke.yaml` running `fuzz_file()` with fixed seed and budget on the toy
harness under AFL++ and under the companion, uploading `.zufuzz/` on failure.
Then the CRAN checklist: `R CMD check --as-cran` on all platforms and
R-devel, `urlchecker`, spelling, no examples or tests writing outside
`tempdir()`, no engine required anywhere in check.

Complete when `pkgdown::check_pkgdown()` passes, README and vignette run from
a clean install with no engine, `R CMD check --as-cran` has no errors,
warnings, or NOTEs on any platform, and `R CMD check` does not start a campaign.

## Stage 12 — Benchmarks

**Depends on:** Stage 11
**Status:** [ ] not started

Work per design §14: `bench/` harnesses (empty, branch-heavy R, thin `.Call`,
one real package); probe, provider, and per-execution overhead measured
separately and per engine (in-process vs worker); guided vs unguided with
≥ 30 predeclared seeds, equal `-runs`/`-E` and equal wall time; sustained-run
RSS; publish configuration, raw results, and the analysis script.

Complete when results reproduce from repository scripts.

## Gate C — Useful exploration

**Depends on:** Stage 12
**Status:** [ ] not passed

Pass when guided search shows a wall-time advantage on branch-heavy R code
under at least one engine and discovers meaningful coverage beyond wrapper
entry in the real package harness. If it fails, profile probe and protocol
cost before touching mutation or scheduling — those belong to the engines.

## Stage 13 — 0.1.0 release

**Depends on:** Gate C; Stages 0–12; companion E3
**Status:** [ ] not started

Work: review every export, condition class, result field, sidecar schema, and
documented limitation against the implementation; freeze instrumentation,
provider, and protocol versions; run the full CI matrix, the Docker image
tests, and the benchmarks; confirm generated data is build-ignored; set
`Version: 0.1.0`, finalize `NEWS.md`; submit `zufuzz` to CRAN; tag
`zufuzz.libfuzzer 0.1.0` and confirm it builds on r-universe for Linux and
macOS.

Complete when Gates A, B, C are recorded as passed, `zufuzz` is accepted on
CRAN with no NOTE, the companion installs from `Additional_repositories` on
a clean machine, and the package claims nothing deferred.

---

## Companion track — `zufuzz.libfuzzer`

Its own repository; depends on `zufuzz`. These are the second revision's
Stages 0–2, Gate A, and the preload half of its Stage 11, unchanged in
substance.

### Companion E0 — Foundation with vendored libFuzzer

**Depends on:** zufuzz Stage 1 (the region accessor)
**Status:** [ ] not started

Work:

- `DESCRIPTION`: `Depends: zufuzz`, `Authors@R` including LLVM as `cph`,
  `SystemRequirements: C++17`, `OS_type: unix`.
- Vendor the libFuzzer file subset from a pinned LLVM release into
  `src/libfuzzer/` (omit Windows, Fuchsia, `FuzzerMain.cpp`,
  `FuzzerInterceptors.cpp`; keep `FuzzerBuiltinsMsvc.h`); `VERSION`,
  `LICENSE.note`, `inst/COPYRIGHTS`.
- `Makevars` with `CXX_STD = CXX17`, plus the `ZUFUZZ_LIBFUZZER_LIB` /
  `ZUFUZZ_CLANG` override; `Makevars.win` refuses with a message.
- **First CI job: system GCC on Ubuntu** compiles the vendored tree with
  R's default flags and asserts `LLVMFuzzerRunDriver` and
  `__sanitizer_cov_8bit_counters_init` are defined and `main` is absent. This
  gates the pin. Apple clang is already measured clean.

Complete when the package installs on Ubuntu (GCC) and macOS (Apple clang),
an internal `.Call` confirms `LLVMFuzzerRunDriver` is linked, the override
links an external archive instead, and `-pedantic` noise, if any, is
silenced locally rather than by patching sources.

### Companion E1 — Bridge: driver, artifacts, signals, unwind

**Depends on:** E0
**Status:** [ ] not started

Work: the in-process `fuzz()` method — argv, the re-exec wrapper script
(sets `R_NO_SEGV_HANDLER=1`), region registration through the accessor,
`LLVMFuzzerRunDriver`; the callback (`RAWSXP` copy, `R_UnwindProtect`/
`R_tryCatch`, return 0); escaped error → the shared diagnostic/sidecar code
from zufuzz Stage 4 → `abort()`; reset `SIGSEGV`, `SIGILL`, `SIGBUS`,
`SIGINT`, `SIGUSR1`, `SIGUSR2` to `SIG_DFL` before the driver, recording what
was replaced.

Fixtures: zufuzz Stage 6's, plus a harness that calls `quit()`.

Complete when: the error fixture produces `crash-<sha1>` with the exact
bytes, the diagnostic, and exit 77; the NULL-dereference fixture and a
`SIGILL`/`SIGBUS` fixture (`__builtin_trap()`, misaligned access) produce
`crash-<sha1>` with and without the wrapper's `R_NO_SEGV_HANDLER`; both hang
fixtures produce `timeout-<sha1>` under `-timeout=2`; `SIGINT` stops the
child cleanly; `-runs=100` exits 0 with the "no interesting inputs" warning
visible when nothing is instrumented; `-fork=1 -ignore_crashes=1 -runs=2000`
over the error fixture keeps going and produces multiple artifacts; `-jobs=2`
and `-minimize_crash=1` re-exec through the wrapper. If `-fork`/`-jobs`
cannot be made to re-exec, drop the claim rather than ship it.

### Companion E2 — In-process sidecars, fingerprint gate, per-input controls

**Depends on:** E1
**Status:** [ ] not started

Work: the bridge honours `ZUFUZZ_EXPECT_FINGERPRINT` (mismatch → return
normally); `before_each`, `rng_seed`, `gc_torture` in the in-process
callback; `coverage_out` from an `atexit` handler as an extra on top of
zufuzz's run-once report; `-minimize_crash` acceleration wired into zufuzz's
`minimize()`.

Complete when the gate makes a two-error fixture abort only on the expected
one; `rng_seed` and `gc_torture` behave as in zufuzz Stage 4 but in-process;
`coverage_out` is produced on the finding and timeout exit paths, not only
on a clean exit; the fingerprint of a finding matches between the companion,
AFL++, and `replay()`.

### Gate A — Bridge viable in R

**Depends on:** E2
**Status:** [ ] not passed

Pass when every E1–E2 fixture behaves identically on Ubuntu (GCC) and macOS
(Apple clang), with and without `LD_PRELOAD` of an ASan runtime on Linux, and
10 000 consecutive escaped errors under `-fork=1 -ignore_crashes=1` leak no
memory beyond libFuzzer's own reporting. If the signal or unwind strategy
fails on a platform, that platform is dropped from the companion rather than
worked around in user documentation — zufuzz itself is unaffected.

### Companion E3 — Preload object and Configuration B

**Depends on:** Gate A
**Status:** [ ] not started

Work: build `zufuzz_preload.so` (libFuzzer plus bridge glue, linked with
`-fsanitize=address` when requested) so libFuzzer's sancov definitions
precede the ASan runtime's; `preload_path()`; `fuzz_file(env =)` sets
`LD_PRELOAD` for the child (`DYLD_INSERT_LIBRARIES` on macOS, expected to hit
SIP); the startup check on `Loaded N modules (M inline 8-bit counters)`.

Complete when zufuzz Stage 10's companion-path criteria pass in the Docker
image.

### Track N — Native coverage feasibility

**Can start after:** E1 · **Blocks 0.1.0:** no
**Status:** [ ] not started

Unchanged from the second revision, run in the Docker image on the fixture
package (a `.Call` wrapper with several branches and a heap overflow behind a
4-byte magic prefix): build with `-fsanitize=address,fuzzer-no-link`; run
under both companion configurations with the preload; assert M exceeds the R
site count; show R counters constant while native features grow; solve the
magic prefix through native `trace-cmp`; confirm the overflow's artifact
replays to the same `SUMMARY:` line; record toolchain requirements (Clang
version, `compiler-rt`, what GCC-built targets do, whether Apple clang can
work). Use `ZUFUZZ_LIBFUZZER_LIB` to test an ABI-matched clang build against
the vendored one. Decide: support native coverage as a documented feature in
0.2, or restrict it to the Docker image. No experimental code becomes a
package dependency.

---

## 0.1.0 definition of done

A developer can:

1. `install.packages("zufuzz")` from CRAN on Linux, macOS, or Windows, with
   no other tool, and instrument a package, generate objects, replay and
   minimize an artifact, and report coverage.
2. Run `engines()` and see what is available, where it was found, and what
   one command would add the rest.
3. Write `test_one_input` in a script, call `instrument_package()` and
   `fuzz()`, and run it with `Rscript harness.R corpus/ -max_len=… -dict=…`
   (companion) or `afl-fuzz -i corpus -o out -- Rscript harness.R` (AFL++),
   or `fuzz_file("harness.R")` for either — with the same harness file.
4. Consume structured values through `fuzzed_data_provider()`, and fuzz
   functions that take R objects via `r_object()`.
5. Draw those same objects interactively with `draw()`, keep interesting ones
   as corpus seeds with `as_seed()`, and render a crash artifact back into the
   object that caused it with `object_from()`.
6. Get `crash-`/`timeout-`/`oom-` artifacts with sidecars for R errors,
   native crashes, R and native hangs, and memory blow-ups — with the same
   names and sidecars on every engine.
7. Watch the companion engine solve prefix and magic-string checks in
   instrumented R code.
8. Run the same harness as an `afl-fuzz` worker inside a sanitized R build,
   with nothing preloaded, and get native findings as artifacts.
9. `replay()` an artifact in a fresh process and `minimize()` a confirmed
   R-error finding without changing its fingerprint, on any platform.
10. Use `fuzz_file()` in CI and distinguish budget, finding, interrupted, and
    infrastructure outcomes.

Each is covered by deterministic automated tests, and items 1, 2, 4, 5, 9, and
10 run inside `R CMD check` with no engine installed.
