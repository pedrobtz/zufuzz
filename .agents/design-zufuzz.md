# zufuzz: coverage-guided fuzzing for R, in the style of Atheris and Ruzzy

**Status:** design, third revision, 2026-09-11. Nothing below is implemented.
**Companion:** [roadmap.md](roadmap.md) (stages, gates, and completion criteria).

The third revision changes the *packaging*, not the model: the engine leaves
the CRAN package. §1 has the table of what changed and why; §13 and §15 carry
the new layout. Instrumentation (§5), the provider and generator (§11), the
reproduction guarantees (§9), and the harness rules (§3) are unchanged from
the second revision.

## 0. Goal and the model we are copying

`zufuzz` should give an R developer what [Atheris](https://github.com/google/atheris)
gives a Python developer and [Ruzzy](https://github.com/trailofbits/ruzzy) gives a
Ruby developer: write a small `test_one_input(data)` function, run it under
libFuzzer, and get coverage guidance for interpreted code, sanitizer-detected bugs
in native code, dictionaries, corpus management, crash artifacts, timeouts, memory
limits, minimization, and parallel jobs. On top of that, add the pieces that are
specific to R: structured replay, finding metadata, a conservative crash
fingerprint, and detection of R-specific bug classes (GC/PROTECT errors) that no
sanitizer sees.

Both reference projects share one architecture — an in-process bridge that
links libFuzzer and drives it through `LLVMFuzzerRunDriver` — and the second
revision adopted it wholesale. The third revision keeps that model and splits
the *packaging*, because CRAN's rules for compiled code, and an R audience on
Windows and stock toolchains, make a single package impossible:

```text
harness script                          Rscript harness.R corpus/ …
  |  test_one_input(bytes)              <- user code, in-process
  v
zufuzz  (CRAN)                          engine-neutral front end
  |  - instruments R code so probes bump a counter region (counters.c)
  |  - FuzzedDataProvider and R object generation (fdp.c)
  |  - fuzz(): run-once mode, or the persistent loop of an attached supervisor
  |  - fuzz_file() / engines(): find an engine, launch, classify, sidecars
  |  - replay(), minimize(): engine-neutral, R-side
  |  - NO exit(), abort(), stderr writes, or vendored engine in zufuzz.so
  |
  |   seam 1: counter region  (address + size + sink mode)
  |   seam 2: launcher        (argv, artifact directory, exit classification)
  |
  +--> zufuzz.libfuzzer (r-universe)    in-process: vendored libFuzzer, bridge.cpp,
  |                                     LLVMFuzzerRunDriver, signals, unwind, abort(),
  |                                     preload object. Linux + macOS. Recommended.
  +--> AFL++ (SystemRequirements)       worker: zufuzz speaks the fork-server /
  |                                     shared-memory protocol itself (~100 lines of
  |                                     C, nothing vendored); afl-tmin, afl-cmin reused.
  +--> (none)                           Windows, or nothing installed: run-once mode,
                                        replay, minimize, provider, generator, coverage.
```

The important consequence is unchanged: **zufuzz implements no mutator, no
corpus store, no scheduler, and no timeout supervisor.** It implements the R
instrumentation, the counter sink, the R-side data provider, the R-side
reproduction tooling, the launcher, and — new in this revision — the *child*
half of one worker-engine protocol. The libFuzzer bridge is exactly what the
second revision described, moved into a companion package where
`R CMD check`'s compiled-code NOTE does not matter.

Prior art for the split is Atheris itself: `atheris.native` (instrumentation,
provider; no libFuzzer linked) is a separate extension from
`atheris.core_with_libfuzzer`, and `LoadCoreModule()` chooses at run time. For
the worker half, python-afl implements AFL's fork server and coverage bitmap
for Python in 235 lines of Cython, with a 22-line shell launcher.

How those pieces are layered — which parts are C, which are R, which package
each lives in, and which work without any engine — is §15.

### Feature parity target

Cells reflect each project's public README at time of writing; verify before
quoting externally.

| Capability | Atheris | Ruzzy | zufuzz 0.1 | zufuzz later |
| --- | --- | --- | --- | --- |
| libFuzzer engine, flags, corpus dirs, `-dict`, artifacts | yes | yes | yes, through the `zufuzz.libfuzzer` companion package | |
| Second engine, worker-process, no clang and no vendored C++ | — | — | AFL++ via `engine = "afl"` | |
| Runs with no engine installed (replay, minimize, generate, coverage) | no | no | yes | |
| Interpreted-code coverage feedback | bytecode rewriting | Ruby `TracePoint` | R AST rewriting → 8-bit counters | |
| Comparison tracing for interpreted code (solves magic bytes) | yes (bytecode `COMPARE_OP` tracing; not prominent in its README) | — | yes (`==`, `identical`, `%in%`, `startsWith`, `switch`, fixed `grepl`) | regex hooks |
| `FuzzedDataProvider` | yes | yes | yes | |
| Native extensions under ASan/UBSan | yes (Clang, preload) | yes (Clang, preload) | documented configurations; the worker path needs no preload; preload helper in the companion | `sanitizer_build()` |
| Native coverage (`-fsanitize=fuzzer-no-link`) | yes | yes | feasibility track N | supported |
| Custom mutator / crossover | yes | — | bridge exports the hooks | R-level API |
| `-jobs`, `-fork`, `-merge`, `-minimize_crash` | not documented | not documented | libFuzzer via re-exec wrapper in the companion (**unproven — companion Stage E1 gate**); AFL++ `-M`/`-S`, `afl-cmin`, `afl-tmin` | |
| Instrument everything already loaded | `instrument_all()` | — | `instrument_all()`, zufuzz self-excluded | |
| Instrument a module and its dependencies | `instrument_imports()` (import hook) | — | `instrument_package(recursive = TRUE)` over `Imports`/`Depends` | |
| Coverage report from a campaign | `-atheris_runs` + `coverage.py` | — | `fuzz(coverage_out =)`, `covr`-compatible | |
| Uncaught exception → crash artifact | yes | yes | yes, plus JSON sidecar | |
| Structured replay and finding metadata | — | — | yes | |
| One-liner over a package function (`fuzz_function()`) | — | — | yes | |
| Byte-driven generation of native language objects | — | — | yes (`r_object()`) | `adversarial` level |
| Interactive generation without the engine | — | — | yes (`draw()`) | |
| Fingerprint-gated minimization (same bug only) | — | — | yes | |
| RNG reset per input | — | — | yes | |
| GC torture for PROTECT bugs | n/a | n/a | yes | |
| Windows | no | Docker only | installs and checks clean; instrument, provider, generator, replay, minimize, coverage all work; no campaign engine (WSL documented) | |

### Where we deliberately differ from Atheris

Four differences are choices, not omissions, and each has a reason rooted in R:

- **No `instrument_imports()` equivalent by import hook.** R has no import-time
  hook comparable to Python's; namespaces are loaded, not imported. The intent
  — "instrument this and what it pulls in" — becomes
  `instrument_package(pkg, recursive = TRUE)`, walking `Imports`/`Depends`
  after `library()`. Document the timing requirement: selection happens after
  loading, before `fuzz()`.
- **`instrument_all()` must exclude zufuzz itself.** Atheris can instrument
  every loaded Python function safely because its engine is C. Parts of zufuzz
  that run per input — the provider, object assembly, the callback wrapper —
  are R, so instrumenting everything would feed the engine's own execution
  back as target coverage. `instrument_all()` therefore always excludes
  `zufuzz`, and excludes base and recommended packages by default (opt in with
  `include_base = TRUE`, and expect noise and cost).
- **Comparison hooks are always on, not opt-in.** Atheris gates `"RegEx"` and
  `"str"` behind `enabled_hooks` as experimental. zufuzz applies its fixed
  comparison list inside instrumented closures by default, because solving
  string equality is the main reason R feedback is worth having; the escape
  hatch is `instrument(compare = FALSE)` when a semantic difference is
  suspected. Regex hooks stay deferred, as in Atheris.
- **Sanitized-R story is better than Atheris's.** Atheris needs CPython patch
  files (documented for 3.8.6 only) for full native coverage. R already has
  community sanitized builds (`rocker/r-devel-san`, `wch1/r-debug`), so
  Configuration A (§10) avoids patching an interpreter entirely.

One area where zufuzz claims **more** than Atheris, and must therefore prove
it: Atheris documents neither `-fork` nor `-jobs`, plausibly because
re-executing an interpreter script through `argv[0]` is awkward. libFuzzer
builds its re-exec command from the original `argv` (`Command Cmd(Args)`), so
the wrapper-script approach should work — but it is unverified, and companion
Stage E1 does not complete until `-fork`, `-jobs`, and `-minimize_crash` all
re-exec correctly. If they cannot, drop the claim rather than shipping it.
The AFL++ engine does not have this problem: `afl-fuzz -M/-S` parallelism is
separate processes by construction.

## 1. What changed between revisions, and why

### First → second revision (the engine)

| First revision | Second revision | Reason |
| --- | --- | --- |
| Custom R mutation engine, C coverage collector, libFuzzer "evaluated later". | libFuzzer vendored into `src/` and driven through `LLVMFuzzerRunDriver`. | Parity with the reference projects; removes ~half the roadmap; libFuzzer's mutator, TORC/value profile, and length control are far beyond what a first R engine would reach. Precedent for vendoring libFuzzer source: Rust `libfuzzer-sys`, Java Jazzer. |
| Supervised persistent callr worker with one-input-at-a-time IPC. | In-process execution, as in Atheris/Ruzzy. Crash resilience via libFuzzer `-fork`/`-jobs` and a thin `Rscript` launcher for in-session use and CI. | Per-input IPC was the dominant cost risk of the old design. libFuzzer's `-timeout` (SIGALRM) and `-rss_limit_mb` already cover non-cooperative hangs and memory blow-ups without a supervisor. |
| Harness = file whose last expression is a manifest list; closures forbidden. | Harness = ordinary R script that calls `zufuzz::fuzz(test_one_input)`; run with `Rscript harness.R corpus/ -flags`. | Same shape as `python target.py corpus/` and `ruby target.rb corpus/`. Closures are fine because nothing is serialized across processes. |
| Explicit function selection only, no package-wide instrumentation. | `instrument_package("pkg")` instruments every namespace closure the conservative transformer supports, plus S3 method table entries; explicit selection remains available. | `covr` rewrites whole packages this way across CRAN; scale is not the transparency risk, unsupported constructs are, and the transformer already skips those. |
| No comparison feedback; long string comparisons acknowledged as unsolvable. | Comparison probes forward to `__sanitizer_cov_trace_cmp*` and `__sanitizer_weak_hook_memcmp/strcmp/memmem`. | This is the single most important Atheris feature for interpreted targets. |
| Structured data consumer deferred. | `fuzzed_data_provider()` in 0.1, mirroring the LLVM/Atheris provider. | Most real harnesses need more than one string. |
| Fresh-worker confirmation of every coverage discovery. | Dropped. libFuzzer tolerates unstable coverage by design. | It existed to protect a custom scheduler that no longer exists. |
| Custom SHA-256 corpus, locks, atomic publication. | libFuzzer's corpus and artifact conventions (SHA-1 names, `crash-`/`timeout-`/`oom-` prefixes, `-artifact_prefix`). zufuzz adds JSON sidecars. | Compatibility with OSS-Fuzz/ClusterFuzz-style tooling and with what users of Atheris already know. |
| Minimization implemented from scratch with a conservative fingerprint. | `-minimize_crash=1` driven by libFuzzer, made conservative by an expected-fingerprint gate in the bridge. | Keeps the good idea (never switch bugs while shrinking) at a fraction of the cost. |

### Second → third revision (the packaging)

Every row below was decided on measurements or on reading the prior art's
source, not on general impressions; the specific evidence is in the Reason
column so it is not re-litigated.

| Second revision | Third revision | Reason |
| --- | --- | --- |
| One package; libFuzzer vendored into `src/`; "CRAN is not a 0.1.0 target". | CRAN package `zufuzz` contains no engine. `zufuzz.libfuzzer` (r-universe) carries the vendored engine, `bridge.cpp`, signals, unwind, `abort()`, preload. | `R CMD check` NOTEs compiled code that calls `exit`/`abort`/`_exit` or writes to stderr, and CRAN requires justification — hardest for the package's *own* `abort()`. Splitting puts every such call in a package that is never submitted. Same split as Atheris `native` vs `core_with_libfuzzer`. Vendoring itself was never the problem: the engine is ~100 KB gzipped (less than `processx`) and compiles clean on stock Apple clang with zero diagnostics. |
| libFuzzer only. | Engine abstraction with exactly two seams — counter sink and launcher — behind `engine = c("auto", "libfuzzer", "afl", "none")`. The AFL++ *child* protocol is implemented inside `zufuzz` in plain C. | The seams are cheap (python-afl: 235 lines), and the worker model runs on a stock-GCC Linux box, and inside a sanitized R build, with nothing vendored and no preload. A second engine must reach zufuzz through a coverage interface that is stable and externally observable — AFL's is a flat `uint8_t[65536]` behind `__AFL_SHM_ID`, unchanged for a decade. Considered and rejected: **LibAFL** (requires *nightly* Rust and `llvm-tools`; ~680 crates in `Cargo.lock`; CRAN's Rust policy expects ≥ 2-year-old cargo); **clang-supplied libFuzzer** (Apple clang ships ASan and profile runtimes and no fuzzer archive at all — measured; Atheris and Ruzzy both document the resulting "install LLVM from Homebrew" tax); **a minimal in-package engine** (the first revision; still rejected, see §2). |
| `fuzz()` never returns. | `fuzz()` returns only in run-once mode. Under an attached supervisor it runs the persistent loop *in R*; under the companion it never returns, as before. | A loop in R needs no `R_UnwindProtect` in the CRAN package: escaped errors are caught by `tryCatch` in the loop, the sidecar is written, and the process signals the crash with `tools::pskill(Sys.getpid(), tools::SIGABRT)` — base R, no compiled `abort()`. |
| `minimize()` drives libFuzzer `-minimize_crash=1` behind the fingerprint gate. | Engine-neutral R-side reducer with the same gate; `-minimize_crash` and `afl-tmin` are accelerators when present. | Must work on Windows and with no engine. Neither libFuzzer's minimizer nor `afl-tmin` has the fingerprint gate: both treat any death as "still crashes" and will silently switch bugs while shrinking. |
| `fuzz_file()` classifies by libFuzzer's exit code. | Classifies by scanning the artifact directory; the exit code corroborates. | Only libFuzzer encodes the outcome in its exit status; `afl-fuzz` exits 0 whether or not it found crashes, and run-once mode returns normally by design. Artifacts on disk are the one piece of evidence every engine produces. |
| `coverage_out` is dumped from an `atexit` handler in the bridge. | `coverage_out` is a property of run-once mode: run a set of inputs once, report what they reached. Engine-free. | Supervisors stop workers with `SIGKILL`, so `atexit` never fires. Run-once is deterministic, testable inside `R CMD check`, and works on Windows. The companion keeps its `atexit` dump as an extra. |
| SHA-1 from the vendored `FuzzerSHA1.cpp`. | `digest::digest(algo = "sha1", serialize = FALSE)`. | The vendored engine left the CRAN package; artifact names stay libFuzzer-compatible. |
| Windows: engine disabled, replay only. | Windows: the whole CRAN package minus campaigns; `engines()` says so explicitly. | libFuzzer's Windows sources are MSVC-only (`__pragma(comment(linker, "/alternatename:…"))`, `__declspec(allocate(…))`) and cannot build under Rtools' mingw; AFL++ is WSL; LibAFL needs nightly Rust plus MSVC-style sancov flags. Nothing exists for the Rtools toolchain. Record that, rather than "ideally a Windows backend". |
| Sanitized configurations need a preload object. | Worker path: a sanitized R build simply *is* the worker — no libFuzzer in the process, no sancov symbol conflict, no preload. Companion path unchanged (§10). | The preload exists only because libFuzzer and the ASan runtime both define the sancov callbacks. The worker child references none of them. |

What did **not** change: the conservative AST transformation rules, the
`substitute()` hazard analysis, the harness oracle rules, the three reproduction
guarantees, the conservative fingerprint, the raw-bytes-first rule for text, the
benchmark discipline, the gate mindset, and the whole design of the libFuzzer
bridge — which now lives in the companion package, verbatim.

## 2. Product boundary

### 0.1.0 includes

**`zufuzz` (CRAN):**

- `fuzz(test_one_input, engine =)`: the harness entry point. Run-once mode
  with no engine; the persistent loop under an attached AFL++ supervisor;
  in-process libFuzzer when the companion is loaded.
- `instrument()` / `instrument_package(recursive =)` / `instrument_all()`:
  R coverage feedback via AST rewriting into a counter region whose sink is
  chosen by the engine, plus comparison tracing (libFuzzer engine; see §5).
- `coverage_out`: a `covr`-compatible report of what a set of inputs reached,
  produced by run-once mode.
- `fuzzed_data_provider()`: deterministic structured consumption of raw bytes.
- `r_object()` / `$consume_object()` / `draw()` / `as_seed()` / `object_from()`:
  byte-driven R object generation at `strict` and `nasty` levels, usable in a
  campaign and in an interactive session.
- Uncaught R error → diagnostic, JSON sidecar, `crash-<sha1>` artifact, on
  every engine.
- `engines()`: which engines are available, where each was found, and what to
  install for the rest.
- `fuzz_file(engine =)`: launcher that runs a harness under the chosen engine,
  classifies the outcome from the artifact directory, and returns a
  `zufuzz_result`.
- `fuzz_function()`: the one-liner over a package function.
- `replay()`: fresh-process, uninstrumented execution of an artifact through
  the same harness — zufuzz's own run-once mode, so it needs no engine.
- `minimize()`: engine-neutral, fingerprint-gated reduction; uses
  `-minimize_crash` or `afl-tmin` to go faster when they exist.
- The AFL++ child protocol (fork server, shared-memory bitmap, persistent
  mode) in plain C, dormant unless a supervisor is attached.
- Optional per-input RNG reset and GC torture.
- Documented sanitizer configurations (§10): the worker path with a sanitized
  R build needs nothing else; the companion path is documented with it.
- Installs, loads, and passes `R CMD check --as-cran` with no compiled-code
  NOTE on Linux, macOS, and Windows, with no engine present.

**`zufuzz.libfuzzer` (r-universe):**

- Vendored libFuzzer from a pinned LLVM release; `bridge.cpp`;
  `LLVMFuzzerRunDriver`; signal reset; unwind protection; `abort()` on an
  escaped error with the fingerprint gate; the re-exec wrapper for
  `-fork`/`-jobs`/`-minimize_crash`; `preload_path()`. Linux and macOS.
- Everything §4's in-process section and §10's preload section describe.

### 0.1.0 excludes

Native coverage feedback as a supported feature (track N decides), the
`adversarial` validity level (needs its triage policy proven first),
`sanitizer_build()`, `install_engine()` (0.2 — 0.1 prints the package-manager
command), a LibAFL backend, comparison tracing on the AFL++
engine (needs CmpLog map writing; 0.2), an R-level custom mutator API, regex
hooks, S4/R6/RC method instrumentation, and any campaign engine on Windows.

A minimal in-package engine — the only route to native Windows campaigns —
stays rejected. It is the first revision's design; it would be a mutator,
corpus, and scheduler owned forever and outperformed by every engine above.
The two seams mean it could be added later as one more backend without
touching anything else, so the decision is reversible without being paid for.

`zufuzz` complements unit and property tests. It supplies input search and
feedback; the harness defines the correctness property.

## 3. Harness and public API

### A harness is a script

```r
# fuzz/parse_json.R
library(zufuzz)
library(zujson)

instrument_package("zujson")           # no-op when ZUFUZZ_NO_INSTRUMENT=1 (replay)

test_one_input <- function(data) {
  fdp <- fuzzed_data_provider(data)
  text <- fdp$consume_string(fdp$remaining_bytes())
  parsed <- tryCatch(zujson::parse(text), zujson_error = function(e) NULL)
  if (!is.null(parsed)) {
    # invalid input may be rejected; a round-trip failure may not
    stopifnot(identical(zujson::parse(zujson::serialize(parsed)), parsed))
  }
}

fuzz(test_one_input)                    # args default to commandArgs(trailingOnly = TRUE)
```

```sh
Rscript fuzz/parse_json.R fuzz/corpus/parse_json -max_len=4096 -dict=fuzz/json.dict -timeout=10
Rscript fuzz/parse_json.R crash-3f2a...        # a file argument = zufuzz's run-once mode; needs no engine
Rscript fuzz/parse_json.R -jobs=4 -fork=4 fuzz/corpus/parse_json          # companion engine
afl-fuzz -i fuzz/corpus/parse_json -o .zufuzz/afl -x fuzz/json.dict -- Rscript fuzz/parse_json.R   # AFL++ engine, same file
```

Rules the harness must follow, unchanged from the first revision:

- `test_one_input` receives one raw vector and its return value is ignored.
- Catch *expected* rejection narrowly around the call allowed to reject. Never
  wrap the whole body in a generic handler. There is no `expected = "error"`.
- Any condition of class `error` that escapes is a finding. Warnings follow R's
  normal policy unless the harness promotes them.
- Per-input state is the harness's job; there is no `reset` hook. Do it inline
  (it is one function call) or via `fuzz(before_each = fn)`.
- External effects (files, network) must be deliberate and use fixtures.

### Public functions

```r
fuzz(
  test_one_input,
  args = commandArgs(trailingOnly = TRUE),
  ...,                                  # engine flags as named args: max_len = 4096, dict = "x.dict"
  engine = c("auto", "libfuzzer", "afl", "none"),
  before_each = NULL,                   # zero-arg closure, run before each input, uncounted
  rng_seed = NULL,                      # integer: restore this R RNG state before each input
  gc_torture = FALSE,                   # TRUE or an integer step for gctorture2()
  artifact_dir = NULL,                  # default ".zufuzz/artifacts/"
  coverage_out = NULL,                  # run-once mode: write the hit-site report here
  quiet = FALSE
)

instrument(..., compare = TRUE)         # "pkg::fn", "pkg:::fn", or a bare name in the calling env
instrument_package(pkg, exclude = character(), recursive = FALSE)
instrument_all(exclude = character(), include_base = FALSE)   # zufuzz always excluded
instrumentation_report()                # what was selected, replaced, skipped, and how many sites

fuzzed_data_provider(data)             # $consume_object(spec) included
r_object(types, max_len, max_depth, validity, ...)   # declarative spec
draw(spec, n = 1, seed = NULL, bytes = NULL)         # interactive; no engine needed
as_seed(x, corpus)                     # save a drawn object's bytes as a corpus seed
object_from(artifact, spec)            # render an artifact back into the R object

engines()                              # data frame: engine, available, found_at, install hint
engine_available(engine)               # logical; what tests and fuzz_file() consult

fuzz_file(path, corpus = NULL, args = character(), ..., engine = "auto",
          time_limit = Inf, runs = Inf, artifact_dir = NULL, env = character(),
          coverage = FALSE, quiet = FALSE)
fuzz_function(fn, corpus = NULL, ..., input = c("raw", "string"),
              expect = character(), instrument = NULL, harness_out = NULL)
replay(path, input, ..., instrument = FALSE)
minimize(path, finding, out, runs = 1000, ..., accelerate = TRUE)
```

`zufuzz.libfuzzer` adds only `preload_path()` (§10); its engine is selected
through `fuzz(engine = "libfuzzer")` or `engine = "auto"` when its namespace
is available.

**Engine resolution** for `engine = "auto"`, in order: an attached AFL++
supervisor (`__AFL_SHM_ID` in the environment) → the `zufuzz.libfuzzer`
namespace, if installed → `none` (run-once). `fuzz_file()` resolves the same
way for what to *launch*, but from `options(zufuzz.engine)`,
`ZUFUZZ_AFL_PATH`, the companion namespace, then `Sys.which("afl-fuzz")`;
`engines()` prints that search.

**Flags** go to the engine verbatim. Under `libfuzzer`, `args` is passed after
zufuzz's defaults and named `...` become `-name=value`, appended after `args`
so explicit R arguments win; positional entries are corpus directories or
input files, as in libFuzzer; defaults are `-artifact_prefix=.zufuzz/artifacts/`,
`-print_final_stats=1`, `-timeout=25`. Under `afl`, `fuzz_file()` builds the
`afl-fuzz -i <corpus> -o <out> -t <timeout> -x <dict> -- Rscript harness.R`
line and sets `AFL_SKIP_BIN_CHECK=1` (the target is not an afl-cc binary; this
is what python-afl's launcher does); named `...` map to the corresponding
`afl-fuzz` options where one exists and error otherwise.

**When `fuzz()` returns.** Only in run-once mode (`engine = "none"`, or
positional file arguments and no supervisor): it runs each listed input once,
writes `coverage_out` if asked, and returns invisibly. Under an attached
supervisor it loops until the supervisor stops it (`SIGKILL`, never returns).
Under the companion it never returns: libFuzzer's driver ends every mode with
`exit()` — 0 on an exhausted budget, `-error_exitcode` (77) on a finding,
`-timeout_exitcode` (70) on a timeout — the same contract as `atheris.Fuzz()`.
`fuzz_file()` exists for callers who want a value in every case.

### `fuzz_function()`: the one-liner for package functions

`zufuzz::fuzz(zujson::parse, corpus = "corpus")` cannot work as written:
`test_one_input` receives raw bytes, `corpus` is a positional libFuzzer
argument, and an in-process `fuzz()` would end the caller's session. The
intent is legitimate, so `fuzz_function()` provides it as a generated harness
run through `fuzz_file()`:

```r
res <- fuzz_function(zujson::parse, corpus = "fuzz/corpus/parse",
                     input = "string", expect = "zujson_error", runs = 1e5)
```

- `fn` is resolved by name when its environment is a package namespace
  (`"zujson::parse"`, including `:::` internals); the child process re-resolves
  it. Other closures are serialized with `saveRDS()`; anything they need from
  the caller's global environment is not carried over and fails in the child as
  an `infrastructure` outcome, not a finding. Document this limit prominently.
- `input = "raw"` passes the bytes; `"string"` passes
  `fuzzed_data_provider(data)$consume_string(n)` (UTF-8 policy from §11).
- `expect` names the *specific* condition classes the function may raise for
  bad input; they are caught narrowly around the call. `"error"`,
  `"simpleError"`, and `"condition"` are rejected, preserving the rule that
  there is no generic escape hatch.
- `instrument` defaults to `fn`'s package; `NULL` for a non-package closure.
- `harness_out` writes the generated script to a path so the user can promote
  the one-liner into a real harness; otherwise it lives in `tempdir()` and its
  path is reported in the result.
- Everything else (`...`, `runs`, `time_limit`, artifacts) is `fuzz_file()`.

Validation before anything starts: `test_one_input` is a closure of one
argument; no nested `fuzz()` (an env marker is set for the process); flags
with unsupported values are rejected by the engine itself. `fuzz()` refuses to
run a campaign when `interactive()` is true, because an engine would terminate
or hijack the session; run-once mode is allowed interactively (it is how
`replay()` works), and `fuzz_file()` is the way to run a campaign from a
session.

## 4. Execution models

There are three, selected by `engine`. Two live in `zufuzz`; the third is the
companion package.

### Run-once (`zufuzz`, every platform)

`fuzz()` with no supervisor and no companion: for each positional argument
(a file, or every file in a directory) read the bytes, reset the counter
region, run `before_each` and the closure under `tryCatch`, record the hit
sites. An escaped error produces the diagnostic, the sidecar, and a
`crash-<sha1>` copy of the input in `artifact_dir`, then continues to the next
file — this mode is for replay and coverage, and never kills the process. At
the end, write `coverage_out` if requested and return. This is what `replay()`
and `coverage_out` are built on, it runs inside `R CMD check`, and it is the
whole of Windows.

### Worker (`zufuzz` + an external AFL++ supervisor, Linux and macOS)

The child half of AFL's protocol, implemented in `src/protocol_afl.c` and
`R/fuzz.R`, modelled line for line on python-afl's `afl.pyx`:

1. **Attach.** If `__AFL_SHM_ID` is set: `shmat()` the 64 KiB coverage bitmap
   and switch the counter sink to AFL mode (§6). Then run the deferred fork
   server handshake on file descriptors 198/199: write the 4-byte hello,
   then loop — read the 4-byte "go", `fork()`, report the child pid, wait,
   report the status. This happens *after* `library()` calls and
   `instrument_package()`, so package loading is paid once (AFL's deferred
   forkserver); the persistent-mode variant runs N inputs per fork.
2. **Loop, in R.** `repeat { bytes <- .Call(afl_next_input); tryCatch(run(bytes), error = escaped); .Call(afl_report_ok) }`.
   The C routines are leaves: none evaluates R code, so nothing needs
   `R_UnwindProtect`. Input arrives on stdin (or the `@@` file); the harness
   reads it with `readBin()`.
3. **Escaped error.** `escaped()` writes the diagnostic to the log, the sidecar
   and artifact copy to `artifact_dir`, honours `ZUFUZZ_EXPECT_FINGERPRINT`
   (mismatch → report ok and continue), then
   `tools::pskill(Sys.getpid(), tools::SIGABRT)`. The supervisor sees a
   signal death and records the crash. No compiled code calls `abort()`.
4. **Native crashes, hangs, memory.** The supervisor's: it kills on
   `-t <timeout>` and `-m <memory>`, and any signal death is a crash.
   `R_NO_SEGV_HANDLER=1` is still set by the launcher so R's own handler does
   not turn a segfault into a clean exit.

Artifacts land in AFL's `crashes/`, `hangs/`, and `queue/` with its own
names; `fuzz_file()` imports each crash into `.zufuzz/artifacts/` under the
`crash-<sha1>` name, next to the sidecar the child already wrote (§8).

AFL++ on macOS works but is documented upstream as slower and needing the
crash reporter disabled; it is supported there as a second choice, the
companion being the first.

### In-process (the `zufuzz.libfuzzer` companion, Linux and macOS)

Everything below this heading is the second revision's bridge, unchanged, now
living in the companion package's `src/bridge.cpp`. It obtains the counter
region from `zufuzz` (§6) and registers it with libFuzzer itself.

`src/bridge.cpp` is the analogue of Atheris's `core.cc`. Responsibilities:

1. Build `argv` and call `LLVMFuzzerRunDriver(&argc, &argv, callback)`, which
   does not return.
2. In `callback(data, size)`: allocate a `RAWSXP`, copy bytes, optionally
   restore RNG state, run `before_each`, run the R closure under
   `R_UnwindProtect`/`R_tryCatch` so no R `longjmp` ever crosses libFuzzer's
   C++ frames, then return 0.
3. On an escaped R error, do what Atheris does for an uncaught exception:
   print `==zufuzz== Uncaught R error`, the condition, and a traceback to stderr;
   write the JSON sidecar (§8); flush; call `abort()` so libFuzzer's SIGABRT
   handler saves `crash-<sha1>` and exits with `-error_exitcode`.
4. Expose `LLVMFuzzerCustomMutator` and `LLVMFuzzerCustomCrossOver` that
   delegate to `LLVMFuzzerMutate` unless an R mutator is registered (0.2).

### Signals: the R-specific trap

Verified against R's `src/main/main.c` and libFuzzer's `FuzzerUtilPosix.cpp`:

- R installs one `SA_SIGINFO | SA_ONSTACK` handler for `SIGSEGV`, `SIGILL`,
  `SIGBUS` (alternate stack, C stack overflow reporting) unless the
  environment variable `R_NO_SEGV_HANDLER` is non-empty *when R starts*, and
  unconditionally installs plain `signal()` handlers for `SIGINT`, `SIGUSR1`,
  `SIGUSR2`, `SIGPIPE`.
- libFuzzer's `SetSigaction` does not install its handler over an existing
  one, with one exception in current releases: an upstream `SA_SIGINFO`
  `SIGSEGV` handler is remembered and chained after libFuzzer's own. Older
  releases skipped `SIGSEGV` too, so the pinned version matters.

Without intervention: a segfault is handled (current libFuzzer first, R
second), but `SIGILL`/`SIGBUS` go to R's handler, which prints "caught
segfault" and terminates *without writing the artifact*; Ctrl-C sets R's
interrupt flag instead of stopping libFuzzer; `SIGUSR1` saves a workspace and
quits.

Decision: the re-exec wrapper and `fuzz_file()` set `R_NO_SEGV_HANDLER=1` so R
never installs the alternate-stack handlers, and the bridge resets `SIGSEGV`,
`SIGILL`, `SIGBUS`, `SIGINT`, `SIGUSR1`, `SIGUSR2` to `SIG_DFL` immediately
before `LLVMFuzzerRunDriver` (covering harnesses started without the wrapper).
Both are recorded in the sidecar. Documented losses: R's "C stack usage too
close to the limit" *error* still fires (a stack-depth check, not a signal), but
a genuine C stack overflow becomes a plain segfault artifact; `kill -USR1` no
longer saves a workspace. Under ASan, ASan's handlers are installed before R's
and libFuzzer defers to them; crashes reach libFuzzer through the sanitizer
death callback. Gate A verifies all of this empirically on both platforms.

### Timeouts, memory, interrupts

- `-timeout=N`: libFuzzer's alarm fires in the signal handler, prints, writes
  `timeout-<sha1>`, and `_Exit`s. It does not need R to reach an interrupt
  check, so an R `repeat {}` and a non-cooperative native loop are both caught.
- `-rss_limit_mb`: libFuzzer's RSS thread; touches no R state.
- `-handle_int`: Ctrl-C stops the campaign cleanly; corpus additions are already
  on disk because libFuzzer writes each new unit immediately.
- `-fork=N` / `-jobs=N` / `-minimize_crash=1` re-exec `argv[0]`. Because the
  harness is `Rscript file.R`, the bridge writes a tiny executable wrapper
  (`.zufuzz/bin/<harness-sha1>.sh` → `exec "$R_HOME/bin/Rscript" --vanilla
  "<harness>" "$@"`) and passes it as `argv[0]`. Tests must exercise all three
  modes.

### R-level determinism aids

- `rng_seed`: capture `.Random.seed` once after `set.seed(rng_seed)` and copy it
  back before each input (cheaper than re-seeding). Record RNG kind in metadata.
  Default `NULL` keeps Atheris's behavior (no reset).
- `gc_torture`: `gctorture(TRUE)` or `gctorture2(step)` around the target call.
  This is the R-specific complement to ASan: it exposes missing `PROTECT`s in
  native code that no sanitizer detects. Expect 10–100× slowdown; document
  `gctorture2(step = 50)` as the practical setting.

### Unguided baseline

With nothing instrumented, the pinned libFuzzer prints "WARNING: no
interesting inputs were found so far. Is the code instrumented for coverage?",
seeds itself with a synthetic input, and keeps mutating (older releases exited
here). That warning is the correct signal and must not be masked; the run is
the pure random-mutation baseline and the control arm for Gate C. No separate
engine or API is needed. Under AFL++ the equivalent is `AFL_SKIP_BIN_CHECK=1`
with an all-zero bitmap: `afl-fuzz` keeps running and reports no new paths,
which `fuzz_file()` surfaces the same way.

## 5. R instrumentation

### Selection

- `instrument("pkg::fn")`, `instrument("pkg:::internal")`, `instrument("local_fn")`.
- `instrument_package("pkg", recursive = FALSE)`: every closure bound in the
  namespace, plus entries in `.__S3MethodsTable__.`, minus `exclude`. With
  `recursive = TRUE`, also its `Imports`/`Depends` closure, which is the
  analogue of Atheris's `instrument_imports()`. Study `covr`'s replacement code
  for S3 tables and for the locked-binding dance; do not depend on `covr`.
- `instrument_all(exclude = character(), include_base = FALSE)`: every loaded
  namespace, the analogue of Atheris's `instrument_all()`. `zufuzz` is
  **always** excluded — its provider and object assembly run per input, and
  instrumenting them would feed engine execution back as target coverage. Base
  and recommended packages are excluded unless asked for.
- Replacement happens in the fuzzing process only; `replay()` runs with
  `ZUFUZZ_NO_INSTRUMENT=1`, under which `instrument*()` are no-ops.
- Instrumentation must complete before `fuzz()`; `fuzz()` freezes the counter
  region. A later `instrument()` call is an error.
- Not updated by binding replacement, and reported as such by
  `instrumentation_report()`: closures captured in other closures, imported
  copies in other namespaces, S4 generics/methods, R6/RC objects, active
  bindings. Primitives and builtins cannot be selected.

### Transformation rules (unchanged, still conservative)

Transform a copy of each closure's R body (available through `body()` even
when byte-compiled), preserving formals, environment, and attributes, then
rebind. Assigning a new body drops old bytecode; R's JIT recompiles the
transformed closure on its own. Record `compiler::enableJIT` level in metadata.

Probe placement:

- function entry, and each statement of an explicitly executed `{` block;
- both outcomes of `if`, including a synthesized absent-`else` that preserves
  the invisible `NULL` result;
- loop-body entry for `for`, `while`, `repeat`;
- descend into branches, blocks, loop bodies, and the RHS of `<-`/`=` to a symbol;
- **new:** descend into the *condition* of `if`/`while` only to rewrite
  comparison calls (below); do not otherwise touch conditions;
- leave iterator expressions, arbitrary call arguments, replacement
  assignments, default arguments, and quoted/`bquote`/`substitute` regions alone.

A probe is `.Call(<NativeSymbolInfo literal>, <site id>)` with the symbol
object embedded in the AST as a constant, so nothing user-shadowable is looked
up. `switch()` arms and `&&`/`||` operands remain deferred.

Instrumentation must preserve evaluation count and order, value and
visibility, laziness, error propagation, `return`/`break`/`next`, and
`on.exit`. Rewriting a call *argument* would change what `substitute()` sees,
which is why arguments other than comparison calls in conditions stay intact.
Functions that inspect their own body, `sys.call()`, or shadow control
primitives are outside the transparency contract; report what static analysis
can identify.

### Comparison tracing

Within instrumented closures, calls whose head is literally one of `==`, `!=`,
`identical`, `%in%`, `startsWith`, `endsWith`, `switch` (string form), and
`grepl`/`regexpr` with `fixed = TRUE` are rewritten to a zufuzz wrapper *that
evaluates the original call unchanged* and then forwards operand bytes:

| Operands | Forwarded to |
| --- | --- |
| two length-1 strings, or two raw vectors | `__sanitizer_weak_hook_memcmp(pc, a, b, n, result)` |
| length-1 string vs. small character table (`%in%`, `switch`) | one `strcmp` hook per table element (bounded, e.g. ≤ 64) |
| fixed-pattern search | `__sanitizer_weak_hook_memmem(pc, haystack, hn, needle, nn, result)` |
| two length-1 integers, or doubles that are whole numbers | `__sanitizer_cov_trace_cmp8(a, b)` |

`pc` is a synthetic address `region_base + comparison_site_id` so that
`-use_value_profile=1` distinguishes comparison sites. Dispatch is preserved
because the wrapper calls the original operator; the extra frame is stripped
from reported stacks. Vectorized comparisons are evaluated and not forwarded.
The magic-string fixture (`if (x == "zufuzz-secret")`) solved within a bounded
number of executions is a Gate B pass condition.

### Startup report

`instrumentation_report()` and the first lines of `fuzz()` output list selected
functions, replaced bindings, counter and comparison site counts, skipped
constructs, unsupported binding paths, and the manifest digest. `fuzz()` with
zero instrumented sites and no `-runs`-bounded replay warns loudly that the
run is unguided.

## 6. Coverage representation

- One `uint8_t` region per process, sized from the frozen plan, owned by
  `zufuzz`'s `counters.c`. A probe is one `.Call` into a routine whose body
  depends on the **sink mode**, set once when an engine attaches and never
  changed afterwards (seam 1):
  - `libfuzzer` — the companion obtains `(start, end)` through an exported C
    entry point and registers them with
    `__sanitizer_cov_8bit_counters_init` plus a synthetic
    `__sanitizer_cov_pcs_init` table (libFuzzer wants both; Atheris does the
    same). Probes increment `region[site]`; libFuzzer reads and zeroes it per
    input.
  - `afl` — probes write AFL edge coverage into the attached 64 KiB bitmap:
    `map[site ^ prev]++; prev = site >> 1`. zufuzz's dense site ids feed this
    with no collisions below 64 K sites, which is better than python-afl's
    `hash(file, line) % MAP_SIZE`.
  - `none` — probes increment `region[site]` and nothing reads it but
    `coverage_out`.
  No `.Call` allocates, and `counters.c` references no `__sanitizer_*` symbol
  in any mode: registration is the companion's job. That is what keeps the
  CRAN package free of engine symbols and what makes the worker path work
  inside a sanitized R build with no preload.
- Site identity = (function identity, AST position) in deterministic
  enumeration order (sorted binding names, pre-order walk). Source references
  are display metadata. The manifest digest covers instrumentation version,
  selection, and original body digests, and is recorded in sidecars so
  `-fork`/`-jobs` children can be checked for agreement.
- Hit counts, not presence: libFuzzer buckets counter values, so loop trip
  counts become features for free.
- Nothing is cached across processes: libFuzzer re-executes the corpus at
  startup; a corpus from an older manifest is simply re-run.
- `coverage_out` is a run-once feature: `fuzz(engine = "none",
  coverage_out = )` over a corpus directory reports the hit set of those
  inputs against the site map, answering "what does this corpus reach". It is
  deterministic, engine-free, runs on Windows and inside `R CMD check`, and
  is how a campaign's coverage is reported after the fact (`fuzz_file()`
  offers `coverage = TRUE` to run it over the final corpus). Atheris does the
  same through `-atheris_runs` plus `coverage.py`; the output is shaped for
  `covr`, so existing reporting tools apply. The companion additionally dumps
  from an `atexit` handler, since its `fuzz()` never returns. It is a report,
  not feedback, and not a statement about correctness.

## 7. Mutation, scheduling, dictionaries

All the engine's. Under the companion, users pass `-dict=file`, `-max_len`,
`-len_control`, `-use_value_profile=1`, `-only_ascii=1`, `-seed`; under
AFL++, `-x file`, `-s seed`, `-t`, `-m`, `-p` power schedule. Dictionary
syntax is shared between the two, so one `.dict` file serves both.
`fuzz(dictionary = list(raw, ...))` is sugar that writes a temporary
dictionary file and passes it in whichever form the engine takes. The
custom-mutator hooks are exported by the companion's bridge and delegate to
`LLVMFuzzerMutate` until an R API exists (0.2); AFL++'s
`AFL_CUSTOM_MUTATOR_LIBRARY` is the equivalent seam there and is unused in 0.1.

## 8. Corpus, artifacts, metadata

Layout (libFuzzer conventions plus sidecars):

```text
fuzz/
  parse_json.R
  corpus/parse_json/<sha1>            # libFuzzer-managed, bytes only
  json.dict
.zufuzz/
  artifacts/
    crash-<sha1>                      # libFuzzer writes it; the worker loop / run-once copy the input
    crash-<sha1>.json                 # R errors: written by the loop (worker, run-once) or the bridge (companion)
    crash-<sha1>.log                  # stderr captured by fuzz_file()/replay()
    timeout-<sha1>, oom-<sha1>        # sidecar written by the launcher from the log
  runs/<run-id>.json                  # fuzz_file() campaign record
  afl/<run-id>/                       # AFL++'s own -o directory (queue/, crashes/, hangs/), kept verbatim
  bin/<harness-sha1>.sh               # re-exec wrapper (companion only)
tests/testthat/fixtures/fuzz/issue-17.bin
```

Artifact names are the same on every engine. Under AFL++, `fuzz_file()`
imports each `crashes/id:*` and `hangs/id:*` file into `artifacts/` under its
`crash-<sha1>`/`timeout-<sha1>` name — the sidecar for an R error is already
there, written by the child before it signalled. AFL's directory is left
untouched so its own tools (`afl-cmin`, `afl-tmin`, `afl-whatsup`) keep
working.

Sidecar contents: schema version, artifact SHA-1 and length, outcome kind,
condition classes, message, normalized originating call, traceback (bounded,
truncation marked), fingerprint, harness path and digest, instrumentation
manifest digest and JIT level, `rng_seed`, R version, platform, loaded package
versions and library paths, locale, and the libFuzzer flags. Not the whole
process environment (credentials). Native findings have no R-side sidecar at
crash time; `fuzz_file()` and `replay()` derive one from the sanitizer report
in the log.

SHA-1 comes from `digest::digest(bytes, algo = "sha1", serialize = FALSE)` in
`zufuzz`, so sidecar names match libFuzzer's artifact names without vendoring
its hash; the companion's bridge uses the same function through R.

## 9. Reproduction, findings, minimization

Three distinct guarantees, unchanged:

| Level | Claim |
| --- | --- |
| Input reproduction | The artifact contains exactly the bytes given to the target; base R reads it with `readBin()`. |
| Finding reproduction | A fresh, uninstrumented process running the recorded harness reproduces the failure. Recorded as confirmed / not confirmed / instrumentation-dependent. |
| Campaign determinism | Same engine, flags, `-seed`, corpus, and deterministic target → same decisions for a fixed `-runs`. Time budgets and `-jobs` weaken this. |

`replay(path, input)` runs `Rscript path input` with `ZUFUZZ_NO_INSTRUMENT=1`
in a fresh process, captures stderr, and returns a structured outcome
(normal / R error / timeout / signal / sanitizer report) plus fingerprint and
environment-mismatch notes read from the sidecar. libFuzzer's "run these files
once" mode makes this trivial. `instrument = TRUE` re-runs instrumented to
separate history dependence from instrumentation dependence.

Fingerprint for R errors: outcome kind + specific condition classes + exact
message + normalized originating call with zufuzz and engine frames stripped.
For sanitizer reports: sanitizer category + the `SUMMARY:` line's function. A
bare signal or exit code is too weak to fingerprint.

`minimize(path, finding, out, runs, accelerate)` is engine-neutral. Its core
is an R-side reducer — delta debugging over the bytes, each candidate checked
by `replay()` with `ZUFUZZ_EXPECT_FINGERPRINT=<fp>` set, so a candidate counts
as "still failing" only when the escaped error's fingerprint matches — which
is the property neither libFuzzer's `-minimize_crash` nor `afl-tmin` has:
both treat any death as success and will happily switch bugs. With
`accelerate = TRUE` and an engine present, `minimize()` first runs
`-minimize_crash=1 -runs=<runs> -exact_artifact_path=<out>` (companion; the
bridge honours the same variable and aborts only on a matching fingerprint) or
`afl-tmin` (AFL++), then finishes with the gated reducer so the result is
correct regardless of what the accelerator did. Refuse to minimize unconfirmed
findings, timeouts, and findings whose fingerprint fields were truncated. The
original artifact is never modified. The pure-R path runs on Windows.

`-fork=N -ignore_crashes=1` is the documented way to continue after a finding
and collect many artifacts; no zufuzz-level dedup in 0.1.

## 10. Native code, sanitizers, native coverage

### Three separate capabilities

| Capability | Who provides it | What it establishes |
| --- | --- | --- |
| Catching a native crash and saving the input | libFuzzer (signal handlers, sanitizer death callback) | The exact bytes that killed the process are on disk. Needs no sanitizer. |
| Detecting memory-safety and undefined-behavior bugs that do not crash | ASan / UBSan runtime, compiled into the target package | A defect becomes a report and a process death instead of silent corruption. |
| Native coverage feedback | Clang SanitizerCoverage (`-fsanitize=fuzzer-no-link`) in the target, delivered to libFuzzer | Mutations are retained for new native edges even when the R wrapper takes the same route. |

The first is in 0.1 unconditionally. The second is in 0.1 as documented
configurations plus a helper. The third is Track N; 0.1 documents sanitizer
*detection* only.

This is the same split Atheris and Ruzzy make: neither owns a sanitizer; both
document how to build the extension with sanitizers and how to get the
sanitizer runtime into the process. zufuzz orchestrates sanitizer-enabled
processes rather than owning the sanitizer runtime.

### The worker path needs none of the machinery below

Under `engine = "afl"`, the R process that runs the target is an ordinary
child of `afl-fuzz`. If that R is a sanitized build (Configuration A), the
sanitizer runtime is simply present, its report ends in `SIGABRT` via
`abort_on_error=1`, and the supervisor records a crash. There is no libFuzzer
in the process and `zufuzz`'s `counters.c` references no `__sanitizer_cov_*`
symbol, so the symbol-resolution trap does not arise and nothing is
preloaded. This is the recommended way to run sanitized campaigns in 0.1: the
Docker image runs `afl-fuzz` over a sanitized R. Everything from here to the
end of the preload section applies to the in-process companion only.

### Two ways to get a sanitized R process (Linux first)

**Configuration A — a sanitized R build.** R's own documentation (*Writing R
Extensions*, "Using Address Sanitizer", "Using Undefined Behaviour Sanitizer")
and the community images cover this:

- `rocker/r-devel-san` (GCC, ASan+UBSan), `rocker/r-devel-ubsan-clang`,
- `wch1/r-debug` (`RDsan`, `RDcsan` binaries).

R itself, and every package compiled inside that image, is instrumented. This
is the R community's standard setup for catching exactly the bugs a fuzzer
finds, and it avoids the preload problem below. It is the recommended way to
run sanitized campaigns, and the base of the zufuzz Docker image.

**Configuration B — stock R plus a sanitized target package.** Build only the
target package with sanitizers:

```sh
# ~/.R/Makevars, or withr::with_makevars() around pkgbuild::compile_dll()/R CMD INSTALL
CC  = clang
CXX = clang++
CFLAGS   = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
CXXFLAGS = $(CFLAGS)
LDFLAGS  = -fsanitize=address,undefined
```

The R executable is not instrumented, so the ASan runtime must be loaded
first via `LD_PRELOAD`, exactly as Atheris (`LD_PRELOAD=$(python -c 'import
atheris; print(atheris.path())')/asan_with_fuzzer.so`) and Ruzzy
(`LD_PRELOAD=$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH')`) do.
`zufuzz::preload_path()` returns the object to preload and `fuzz_file(env = )`
sets it for the child. On macOS the equivalent is `DYLD_INSERT_LIBRARIES`,
subject to SIP; Linux is the supported platform for B in 0.1.

**Runtime options that R needs:**

```sh
ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0:allocator_may_return_null=1:abort_on_error=1
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
```

`detect_leaks=0` because R intentionally leaves allocations for the OS at exit
and LSan reports are noise; `allocator_may_return_null=1` so R's own
out-of-memory path is reached instead of an ASan abort; `abort_on_error=1` so
a report ends in `SIGABRT`, which libFuzzer handles. Ruzzy's documented set is
`allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0`; whether R
needs `use_sigaltstack=0` once `R_NO_SEGV_HANDLER` is set is a Stage 10 test.
Record the options in finding metadata.

### The symbol-resolution trap (why Atheris ships `asan_with_fuzzer.so`)

A target compiled with `-fsanitize=fuzzer-no-link` has undefined references to
`__sanitizer_cov_8bit_counters_init`, `__sanitizer_cov_pcs_init`, and
`__sanitizer_cov_trace_cmp*`. The ASan runtime *also* defines these
(`sanitizer_coverage_libcdep_new.cpp`, `SANITIZER_INTERFACE_WEAK_DEF`) so that
ASan-only binaries link; its versions feed sanitizer_common's own coverage
dumper, not libFuzzer. At run time the dynamic linker takes the **first**
definition in search order — executable, then `LD_PRELOAD` objects, then
dependencies — and does not prefer strong over weak.

Consequences for R, where packages are `dlopen`ed `RTLD_LOCAL` by default:

1. If the companion's `zufuzz.libfuzzer.so` (which contains libFuzzer) is
   loaded `RTLD_LOCAL`, a target package loaded afterwards cannot resolve the
   callbacks from it at all. **The companion** therefore loads its DLL with
   `library.dynam(..., local = FALSE)`. `zufuzz` does not need to: the
   companion reaches the counter region through `R_GetCCallable()`, not
   through the dynamic linker (§15).
2. Even then, in Configuration A the ASan runtime is a dependency of the R
   executable and in Configuration B it is preloaded — in both cases it sits
   *before* the companion's shared object in search order, so the target's
   callbacks bind to ASan's definitions and libFuzzer silently sees no native
   coverage.
3. ASan's `memcmp`/`strcmp` interceptors call `__sanitizer_weak_hook_memcmp`
   etc. only if those weak references resolved when ASan loaded; a libFuzzer
   loaded later is invisible to them.

Atheris solves all three by preloading one object that contains libFuzzer and
links the ASan runtime, so libFuzzer's definitions come first. The companion
needs the same: a `zufuzz_preload.so` built alongside its own shared object
(libFuzzer + bridge glue, linked with `-fsanitize=address` when a sanitizer
configuration is requested), returned by `preload_path()`. In Configuration A
the preload still comes before the executable's dependencies, so it works
there too. None of this exists in `zufuzz` itself, which is why the worker
path is immune.

Verification is mandatory and cheap: libFuzzer prints
`INFO: Loaded N modules (M inline 8-bit counters)` at startup. With only R
instrumentation, N = 1 and M = the R site count. Native coverage is present
only if M exceeds that. `fuzz()` records both numbers and warns when a
sanitized configuration was requested but no native counters appeared.

Modules loaded *after* `LLVMFuzzerRunDriver` starts (a `library()` call inside
`test_one_input`) are unsupported in 0.1: load everything before `fuzz()`.

### What sanitizers do not catch in R packages

- **Missing `PROTECT` / premature GC.** Not memory-unsafe from ASan's point of
  view. `fuzz(gc_torture = TRUE)` (or `gctorture2(step)`) makes these
  crash reliably; pair it with ASan for the best signal. Static checking with
  `rchk` is the complement.
- **R API misuse** (wrong `SEXP` type, missing `R_NO_REMAP` issues) is caught
  by R's own checks as R errors, which every execution mode already reports
  as an ordinary R-error finding.
- **Deep recursion in R code** surfaces as R's "C stack usage" error, not as a
  sanitizer report.
- **Leaks**: disabled by policy above.

### Artifacts, replay, and fingerprints for native findings

libFuzzer writes `crash-<sha1>`, `timeout-<sha1>`, `oom-<sha1>` regardless of
how the process died. No R code runs after a sanitizer abort, so there is no
bridge-written sidecar; `fuzz_file()` and `replay()` build one from the log:

- `kind`: `asan`, `ubsan`, `signal`, `timeout`, `oom`;
- `sanitizer_summary`: the `SUMMARY: AddressSanitizer: heap-buffer-overflow …
  in <function>` line;
- `top_frames`: first frames of the sanitizer stack that are not in R itself;
- exit code, signal, options in effect.

Fingerprint = kind + summary category + top in-package frame. A bare signal
with no report is recorded but not fingerprinted, and `minimize()` refuses it.
`minimize()` for sanitizer findings uses `-minimize_crash=1`; libFuzzer treats
any death as "still crashes", so the launcher re-checks the summary line of
the final candidate and reports whether the bug class matched.

Replay: `Rscript harness.R crash-<sha1>` under the same configuration and
preload. `replay()` sets the environment from the sidecar when present and
reports mismatches (different R build, missing preload, different package
versions) without refusing to run.

Regression tests for fixed native bugs read the raw fixture with base R and
call the package directly; they do not depend on zufuzz.

### Platforms and the Docker image

Legend: ✓ measured during the third-revision review · ~ static evidence, to be
verified at the stage named · ✗ ruled out, with the reason recorded in §1.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Builds `zufuzz` (`fdp.c`, `counters.c`, `protocol_afl.c`) | system GCC | Apple clang | Rtools GCC; protocol routines compile as no-ops |
| Builds `zufuzz.libfuzzer` | GCC ~ (GCC builtins throughout; upstream guards `#ifdef __clang__ // avoid gcc warning`) — **companion Stage E0's first CI job** | Apple clang ✓ (19 TUs, zero diagnostics, `LLVMFuzzerRunDriver` exported) | ✗ MSVC-only sources |
| Instruments the target | R AST rewrite → `counters.c`; no compiler involved | same | same |
| Campaign: companion (in-process) | ✓ recommended | ✓ recommended | ✗ |
| Campaign: AFL++ (worker) | ✓ | ~ upstream caveats | ✗ (WSL) |
| ASan/UBSan targets | worker: sanitized R as the worker, no preload; companion: Configuration A or B | companion: needs validation (`DYLD_INSERT_LIBRARIES`, SIP); worker: untested | ✗ |
| Native coverage | Track N, companion + Clang | unlikely without LLVM clang | ✗ |
| No engine: replay, minimize, generate, `coverage_out` | ✓ | ✓ | ✓ |

Ship a `Dockerfile` (based on `rocker/r-devel-ubsan-clang`) with zufuzz, the
preload object, and the fixture, as Ruzzy does. It is the reference
environment for every claim in this section.

### `sanitizer_build()` — deferred to 0.2

```r
zufuzz::sanitizer_build(package = ".", sanitizers = c("address", "undefined"),
                        coverage = TRUE, recover = FALSE, debug = TRUE, lib = NULL)
```

A convenience wrapper that sets `Makevars` via `withr::with_makevars`, calls
`pkgbuild`/`R CMD INSTALL` into a separate library, and prints the environment
lines needed to run. Convenience only; the flags above are the contract.

The staging is: **0.1** — the worker path over a sanitized R build is the
recommended configuration and needs nothing from this section; the companion
catches native crashes in-process, Configurations A and B are documented,
`preload_path()` and sidecars-from-logs ship, and the Docker image is the
reference environment (roadmap Stage 10 and companion E3). **Track N** — the
native coverage experiment and its decision. **0.2** — `sanitizer_build()`,
native coverage if Track N passed, macOS validation.

## 11. Structured inputs: bytes to R values

### FuzzedDataProvider

`fuzzed_data_provider(data)` returns an object with methods, backed by a C
cursor state. Semantics mirror LLVM's `FuzzedDataProvider.h` where R permits
(bytes and strings consumed from the front, integers from the back), so
corpora and intuitions transfer from Atheris users.

| Method | Contract |
| --- | --- |
| `remaining_bytes()` | count |
| `consume_bytes(n)` | raw, min(n, remaining), from the front |
| `consume_remaining_bytes()` | raw |
| `consume_string(n, encoding = c("utf8", "ascii", "bytes"))` | `utf8`: longest valid UTF-8 prefix of n bytes with NULs removed, marked UTF-8; `ascii`: bytes masked to 7 bits; `bytes`: `rawToChar` with NULs removed. All deterministic, all documented, invalid input never errors. |
| `consume_int(bits = 32)` / `consume_int_in_range(min, max)` | R integer in `[-2^31+1, 2^31-1]` (never `NA_integer_`), consumed from the back like LLVM's `ConsumeIntegral` |
| `consume_number_in_range(min, max)` | double |
| `consume_double(allow_special = TRUE)` | double; with probability from one byte returns `NaN`, `±Inf`, `-0`, `NA_real_` |
| `consume_probability()` | double in [0, 1] |
| `consume_bool()` | logical, never `NA` |
| `pick_value(x)` | one element of a vector or list |
| `consume_int_list(n, bits = 32)` | integer vector |

Exhausted input returns zero-length/zero values, never errors. The exact byte
consumption algorithm is versioned and part of the documented API because it
determines corpus compatibility across releases. Atheris additionally offers
unsigned, list-in-range, and float-list variants. The list-returning ones
matter *more* in R than in Python — a vector is the natural R value, not a
special case — so `consume_int_list()`, `consume_double_list()`, and
`consume_probability_list()` ship in 0.1 rather than being deferred. The
Python-specific surrogate variants (`ConsumeUnicodeNoSurrogates`) have no R
analogue; `consume_string(encoding =)` covers that ground.

Raw bytes remain the persisted and mutated representation. `rawToChar()`
caveats from the first revision stand: embedded NULs error, trailing NULs
vanish, and marking a string UTF-8 does not validate it. The provider's
`consume_string` exists so harnesses do not each reinvent a policy.

### Generating R objects

Most R functions take R objects, not bytes. A generator turns the same bytes
into vectors, lists, and attributes, so a coverage-guided campaign can search
the *shape* of an argument rather than only its contents. This is LLVM's
structure-aware fuzzing pattern, and the whole design rests on one rule:

> **The object is a pure, deterministic function of the bytes.** No R RNG, no
> clock, no environment. Bytes in, object out, versioned.

That rule buys four things at once, and losing it loses all four: libFuzzer's
mutations become structural edits; `-minimize_crash` shrinks the *object* by
shrinking its bytes; every object has an exact on-disk representation that
replays; and the same generator runs in an interactive session with no engine
present.

```r
spec <- r_object(
  types      = c("logical", "integer", "double", "character", "list"),
  max_len    = 32,
  max_depth  = 3,
  validity   = c("nasty", "strict", "adversarial")
)

# in a harness
test_one_input <- function(data) {
  fdp <- fuzzed_data_provider(data)
  x <- fdp$consume_object(spec)
  summary(x)
}
```

`r_object()` is a declarative spec, not a generator closure, so it can be
printed, compared, and recorded in finding metadata. The consumption algorithm
is versioned alongside the provider's, because it determines whether an old
corpus still means anything.

### Interactive use

`draw()` is the interactive face of the same machinery:

```r
xs <- zufuzz::draw(spec, n = 20, seed = 42)   # list of 20 objects, reproducible
str(xs[[7]])
attr(xs[[7]], "zufuzz_bytes")                 # the bytes behind it

zufuzz::draw(spec, bytes = as.raw(c(0x01, 0xff, 0x2a)))   # exact reproduction
```

`draw()` needs no libFuzzer, no worker, and no instrumentation, so it works in
a plain session — the generator is engine-independent by construction. `seed`
expands to bytes through an internal PRNG that never touches `.Random.seed`;
`bytes` reproduces an object exactly.

Two flows make this more than a toy:

- `as_seed(x, corpus)` writes the bytes behind a drawn object into a corpus
  directory. Explore interactively, keep the interesting shapes, start the
  campaign from them.
- `object_from(artifact, spec)` renders a crash artifact back into the R object
  that caused it, so triage inspects a value rather than a hexdump.

### Validity levels, and an honesty rule

R lets you build objects that are representable but that no documented
contract accepts. The level is explicit because it changes what a crash means:

| Level | Contains | A crash here is |
| --- | --- | --- |
| `strict` | What base constructors produce: well-formed vectors and lists, no `NA`. | A defect. |
| `nasty` (default) | `strict` plus `NA` of every type, `NaN`, `±Inf`, `-0`, empty and zero-length vectors, very long and duplicated names, non-ASCII and invalid-UTF-8 strings, `latin1`/`UTF-8`/`bytes` encoding marks, `NULL` inside lists, and both ALTREP and materialized forms of the same value (`1:10` versus `c(1L, …)` take different C paths). | A defect. |
| `adversarial` (opt-in) | `nasty` plus objects that lie: a `class` attribute with no matching structure, `dim` inconsistent with length, factor codes outside `levels`, arbitrary attributes on anything. | **Only** a defect if the package documents that it accepts such input. Otherwise it is a hardening observation. |

Objects that are malformed at the C level and unreachable through the R API
are out of scope: that is fuzzing R itself, not the package. The level is
recorded in every sidecar so triage is never guesswork, and `adversarial`
findings are reported under a distinct label rather than mixed into the bug
count.

### Relationship to existing R packages

[`hedgehog`](https://cran.r-project.org/package=hedgehog) (property-based
testing, integrated shrinking) and [`fuzzr`](https://cran.r-project.org/package=fuzzr)
(a fixed battery of awkward arguments) already cover random-input testing, and
`hedgehog` does it well. zufuzz is not trying to replace either. The
difference is the driver: QuickCheck-style generators consume an RNG and shrink
through their own algebra, which cannot be steered by coverage; zufuzz's
generator consumes bytes, so libFuzzer's feedback loop and minimizer apply
directly. Use `hedgehog` for expressive properties over well-formed values; use
zufuzz when you want coverage to find the shape, or when native code is
involved.

## 12. Launcher, results, CI

`fuzz_file()` resolves an engine (§3), builds its command line —
`Rscript --vanilla <harness> <corpus> <args>` for the companion,
`afl-fuzz … -- Rscript --vanilla <harness>` for AFL++ — runs it under
`processx` with `R_NO_SEGV_HANDLER=1`, streams stderr to a log, applies
`time_limit`/`runs` (`-max_total_time`/`-runs` for the companion; `-V`/`-E`
for `afl-fuzz`), and classifies the outcome. **The artifact directory is the evidence;
the exit code only corroborates**, because engines disagree about exit codes
and none of them is the ground truth:

| Evidence, checked in this order | `stop_reason` |
| --- | --- |
| a new `crash-` artifact (companion) or `crashes/id:*` (AFL++) | `finding` |
| a new `timeout-`/`oom-` artifact or `hangs/id:*` | `finding` (kind `timeout` / `oom`) |
| the child was interrupted by the caller | `interrupted` |
| no artifact, and the engine's normal-completion signature is present (libFuzzer's final stats and exit 0; `afl-fuzz`'s exit after `-E`/time limit) | `budget` |
| anything else (harness failed to load, missing package, bad flag, engine not found after all) | `infrastructure` |

A test double — `tests/fixtures/fake-engine.R`, a script that behaves like a
supervisor and writes artifacts on cue — exercises every row inside
`R CMD check` with no real engine installed.

`zufuzz_result` fields: `engine`, `stop_reason`, `finding` (artifact,
sidecar, fingerprint, kind), `executions`, `exec_per_sec`,
`new_units_added`, `peak_rss_mb`, `corpus_dir`, `log`, `elapsed`, and the
engine's final stats verbatim (libFuzzer's `-print_final_stats` block, or
`afl-fuzz`'s `fuzzer_stats` file), with the common fields above parsed out
of whichever it was.
`print()` never labels feature counts "paths". Findings are a distinct stop
reason so CI cannot mistake one for success.

CI layers:

1. Ordinary `testthat` replays committed regression fixtures with base R.
2. A separate smoke workflow runs `fuzz_file()` with fixed `-runs` and `-seed`
   and fails on `finding` or `infrastructure`.
3. Scheduled campaigns persist the corpus and upload artifacts and logs.

Long campaigns never run as examples or in `R CMD check`.

## 13. Packaging constraints

**`zufuzz` — CRAN is a 0.1.0 target, and these are the rules that make it one:**

- No engine, no vendored engine code, no C++. `src/` is `fdp.c`,
  `counters.c`, `protocol_afl.c`, `init.c`, built the same way on every
  platform; the AFL routines compile to no-ops where `<sys/shm.h>` is absent.
- `zufuzz.so` contains no call to `exit`, `abort`, `_exit`, or any stdio
  write. The Stage 0 symbol scan enforces it as a test, so the compiled-code
  NOTE cannot appear, and `R CMD check --as-cran` is clean on Linux, macOS,
  and Windows with no engine installed.
- Engines are external and optional, through CRAN's three sanctioned routes:
  `Suggests: zufuzz.libfuzzer` with
  `Additional_repositories: https://pedrobtz.r-universe.dev` (the pattern
  `INLA` and `cmdstanr` use); `SystemRequirements: AFL++ (optional)` found
  via `Sys.which()`; and, in 0.2, `install_engine()` writing only to
  `tools::R_user_dir("zufuzz", "cache")` after user consent, as `tinytex`
  and `torch` do. Nothing is downloaded or built at install time. No binary
  ships in the source package.
- Every engine-dependent test is `skip_if_not(engine_available(...))`; every
  campaign example is under `@examplesIf`; no vignette starts a campaign;
  the launcher's classification is tested against the fake-engine double.
  CRAN's check machines have no engine and the package must not care.
- Tests write only under `tempdir()`; the `.zufuzz/` directory is created
  only by `fuzz_file()` and `fuzz()`, never by a test or example.
- Minimum R 4.1. Imports: `processx` (launcher), `jsonlite` (sidecars),
  `digest` (SHA-1 artifact names). No `callr`.
- Windows is a supported *installation* platform with a documented
  limitation (no campaign engine; `engines()` says so and points at WSL),
  not an `OS_type: unix` exclusion.

**`zufuzz.libfuzzer` — r-universe, never CRAN; its own repository:**

- libFuzzer is vendored under `src/libfuzzer/` from a pinned LLVM release
  (Apache-2.0 WITH LLVM-exception; record it in `LICENSE.note`/`inst/COPYRIGHTS`
  and `Authors@R` `cph`), verbatim, as a *file subset*: the Windows and
  Fuchsia sources, `FuzzerMain.cpp`, and `FuzzerInterceptors.cpp` are
  omitted; `FuzzerBuiltinsMsvc.h` is kept because `FuzzerUtil.h` includes it
  unconditionally. It builds with a C++17 compiler and needs no LLVM at
  install time (Apple clang measured; GCC is the first CI job). Precedent:
  `libfuzzer-sys`, Jazzer.
- `ZUFUZZ_LIBFUZZER_LIB` (or `ZUFUZZ_CLANG`, resolved through
  `--print-file-name`) links an external archive instead of the vendored
  tree — the escape hatch Atheris has as `$LIBFUZZER_LIB`/`$CLANG_BIN`. It is
  how Track N tests an ABI-matched clang build, and how LibAFL's drop-in
  `libFuzzer.a` can be evaluated without any zufuzz change.
- `R CMD check` will NOTE that compiled code calls `abort`, `exit`, and writes
  to stderr. That is this package's purpose and it is not submitted anywhere
  that objects.
- Linux and macOS only; `Makevars.win` refuses to build with a clear message.
- Depends on `zufuzz` for the counter region and everything R-side; adds no
  R API of its own beyond `preload_path()`.
- Build against libFuzzer's documented *interface* only —
  `LLVMFuzzerRunDriver`, the sancov registration calls, the
  `__sanitizer_weak_hook_*` symbols — never its internals. libFuzzer is in
  maintenance mode upstream (its authors moved to Centipede); interface
  discipline is the hedge, and it is what makes `libafl_libfuzzer`'s
  `libFuzzer.a` a link-time swap.

## 14. Validation and gates

Correctness tests use deterministic fixtures; stochastic discovery lives in
`bench/`. Required evidence:

| Area | Evidence |
| --- | --- |
| CRAN shape | `zufuzz.so` symbol scan finds no `exit`/`abort`/stdio/`__sanitizer_*`; `R CMD check --as-cran` has no compiled-code NOTE on Linux, macOS, Windows with no engine installed; every `stop_reason` reproduced by the fake-engine double inside check. |
| Bridge (companion) | R error → `crash-` artifact + sidecar + error exit; native segfault fixture → `crash-` artifact (with R's handlers reset); R `repeat {}` and native busy loop → `timeout-` artifact; Ctrl-C → clean stop; `-fork`, `-jobs`, `-minimize_crash` re-exec works; no R `longjmp` escapes the callback (run a harness that errors 10 000 times under `-fork=1 -ignore_crashes=1`). |
| Worker protocol (AFL++) | Same fixtures under `afl-fuzz`: R error → child-written sidecar + `crashes/id:*` imported as `crash-<sha1>`; segfault and `pskill(SIGABRT)` both reach the supervisor; hangs → `hangs/` → `timeout-`; fork server survives three `library()` calls before `fuzz()`; 10 000 persistent-mode inputs without RSS growth. |
| Instrumentation semantics | Original vs transformed agree on value, visibility, side effects, laziness, conditions, control transfers; fixtures include missing args, empty bodies, recursion, `on.exit`, byte-compiled input, S3 methods via the table. |
| Feedback | Counters reach the engine (companion: "Loaded 1 modules (N counters)"; AFL++: a non-zero bitmap and new paths); nested-prefix fixture solved by each engine with a fixed seed and budget; magic-string fixture solved via cmp hooks under the companion; the same fixtures are *not* solved by either unguided baseline in that budget. |
| Provider | Every method on empty input, one byte, and boundary ranges; the consumption algorithm matches its written spec byte for byte. |
| Reproduction | Deterministic error fixture confirms via `replay()`; history-dependent fixture reported as unconfirmed; fingerprint stable across processes. |
| Minimization | Reducible fixture shrinks and reconfirms; a candidate that changes the error is rejected; original untouched. |
| Launcher | Each `stop_reason` from a fixture; interrupt cleans up the child. |

Gates (details in the roadmap): **A** — bridge viable in R (signals, unwind,
artifacts, timeouts); gates the companion only; **B** — trustworthy R
feedback (semantics, counters, comparison tracing) under both engines;
**C** — measured usefulness (guided vs unguided, ≥ 30 predeclared seeds,
equal-attempt and equal-wall-time, on branch-heavy R code and a
representative package); **N** — native coverage feasibility.

Benchmarks: empty target, branch-heavy R target, thin `.Call` wrapper, one real
package. Separate probe overhead, provider overhead, and per-execution bridge
overhead. Report OS, R/compiler versions, hardware, flags, and seeds. Report
time-to-finding over all runs, not only successful ones.

## 15. Architecture and implementation map

### Four layers, one direction of dependency

```text
 zufuzz (CRAN)
            R layer  (R/)                        depends on
 ---------------------------------------------------------------------------
  fuzz.R           fuzz(): run-once, worker loop -> counters.c, protocol_afl.c
  engines.R        engines(), engine_available() -> nothing native
  instrument.R     instrument*()                 -> plants .Call into counters.c
  fdp.R objects.R  draw(), r_object(), FDP       -> fdp.c                  ONLY
  launcher.R       fuzz_file(), fuzz_function()
  replay.R         replay(), minimize()          -> processx (no native at all)
 ---------------------------------------------------------------------------
          native layer  (src/)          — no exit/abort/stdio, no C++
 ---------------------------------------------------------------------------
  counters.c       counter region, probe routine with three sink modes,
                   exported (start, end) accessor for engines    <- no engine symbols
  protocol_afl.c   shmat, fork server on fd 198/199, next_input, report
  fdp.c            byte cursor + primitive decoding              <- no engine dependency
 ===========================================================================
 zufuzz.libfuzzer (r-universe)            depends on zufuzz, downward only
 ---------------------------------------------------------------------------
  bridge.cpp   LLVMFuzzerRunDriver, callback, unwind, signal reset, abort,
               registers zufuzz's region with __sanitizer_cov_8bit_counters_init,
               cmp/memcmp/memmem forwarding, preload glue
  libfuzzer/   vendored, pinned                      <- depended on by bridge only
```

Arrows never point upward, never cross the package boundary upward, and
never point sideways into `libfuzzer/` except from `bridge.cpp`. `counters.c`
exports the region and knows the sink modes; it does not know any engine's
symbols. That single rule is what keeps `zufuzz` on CRAN, what makes the
value layer usable on its own, and what lets a sanitized R build be an AFL++
worker with nothing preloaded.

### Three entry paths, one launcher

```text
 companion (in-process)        worker (AFL++)                   run-once (no engine)
 ----------------------        --------------------------       ----------------------
 Rscript harness.R corpus/     afl-fuzz -i -o -- Rscript h.R    Rscript harness.R crash-x
   instrument_package()          instrument_package()             instrument_package()
   fuzz()                        fuzz()  -> attach: shmat,        fuzz()  -> for each file:
     |                             fork server on 198/199           run closure, record hits
     v                             |                                |
   LLVMFuzzerRunDriver             v                                v
     | never returns             repeat: next_input ->            coverage_out, return
     v                             tryCatch(closure)
   callback -> R closure           |  error -> sidecar ->
     |                             |  pskill(SIGABRT)
     v                             v
   abort() -> crash-<sha1>       afl-fuzz records crashes/id:*
                                                 \
                    fuzz_file() / fuzz_function() —— processx —— any of the three
                    replay() / minimize()  —————— run-once, always
                                                   |
                                                   v
                              artifact directory scan -> zufuzz_result
```

Only the companion column ends the process. The worker column is stopped by
its supervisor. The run-once column returns, and it is the only column
`replay()` and `minimize()` ever use, which is why they need no engine and
work on Windows. The value layer (below) belongs to none of them and runs
anywhere.

### Is `draw()` pure R? No — and deliberately so

`draw()` is R for spec interpretation and object assembly, C for the byte
cursor and primitive decoding. It loads no libFuzzer, spawns no process, and
needs no instrumentation.

The rule behind the split:

> **The byte-to-value mapping is implemented exactly once, in `src/fdp.c`.**
> `draw()` and `fdp$consume_object()` are two front doors onto the same code.

A pure-R `draw()` would mean two implementations of that mapping — one for
interactive use, one for the campaign hot loop — which would drift and
silently break "same bytes, same object", the invariant the whole structured-
input design rests on (§11). One implementation also keeps the per-input cost
in C, where a campaign executes it millions of times.

Object *assembly* (attributes, encoding marks, ALTREP versus materialized
forms, factor construction) stays in R because it is fiddly and rarely the
bottleneck. That split is provisional: Stage 12 measures it, and assembly moves
to C only if the benchmark says so.

### What each export actually needs

| Export | Native code | Needs an engine | Usable in a live session | Windows |
| --- | --- | --- | --- | --- |
| `r_object()` | none (a spec object) | no | yes | yes |
| `fuzzed_data_provider()` | `fdp.c` | no | yes | yes |
| `draw()`, `as_seed()`, `object_from()` | `fdp.c` | no | yes | yes |
| `instrument()`, `instrument_package()`, `instrumentation_report()` | plants probes calling `counters.c` | no | yes (inert without a campaign) | yes |
| `engines()`, `engine_available()` | none | no | yes | yes (reports none) |
| `fuzz()` run-once / `coverage_out` | `counters.c` | no | yes | yes |
| `fuzz()` under AFL++ | `counters.c`, `protocol_afl.c` | supervisor attached | **no** — refuses `interactive()` | no |
| `fuzz()` under the companion | `bridge.cpp` (companion) | **yes** | **no — exits the process** | no |
| `fuzz_file()`, `fuzz_function()` | none in the caller | in the child, any engine | yes | no (`infrastructure`: no engine) |
| `replay()`, `minimize()` | none in the caller | no — run-once in the child | yes | yes |
| `preload_path()` (companion) | none | no | yes | no |

Three consequences worth stating plainly: the generator, provider,
instrumentation, replay, minimization, and coverage reporting work on Windows
and in any interactive session even though no engine does; nothing a user
calls interactively can take the session down, because both campaign modes of
`fuzz()` refuse `interactive()`; and the CRAN package can be fully tested by
`R CMD check` on a machine with no engine, because every engine-free row above
is a real code path, not a stub.

### File responsibilities

**`zufuzz` (CRAN):**

| Location | Responsibility |
| --- | --- |
| `src/counters.c` | Counter region allocation, probe hit routine with the three sink modes, `(start, end)` accessor exported for engines. No engine symbols. |
| `src/protocol_afl.c` | `shmat` of the AFL bitmap, fork server on fds 198/199, `next_input`, `report`. Leaf routines only; no-ops on Windows. |
| `src/fdp.c` | Provider cursor and consumption algorithm, including object generation. |
| `src/init.c` | Routine registration (`R_useDynamicSymbols(FALSE)`, `R_forceSymbols(TRUE)` — so a planted probe cannot be redirected by anything a user can shadow); `R_RegisterCCallable()` of the counter-region accessor for the companion. |
| `R/fuzz.R` | `fuzz()`: engine resolution, run-once mode, the worker loop, escaped-error handling and `pskill`, RNG and GC torture, `coverage_out`. |
| `R/engines.R` | `engines()`, `engine_available()`, the search order, install hints. |
| `R/instrument.R` | Planning, transformation, comparison rewriting, binding replacement, report. |
| `R/fdp.R`, `R/objects.R` | R face of the provider; `r_object()` spec, assembly, validity levels, `draw()`, `as_seed()`, `object_from()`. |
| `R/launcher.R` | `fuzz_file()`: per-engine command lines, artifact-directory classification, AFL import, `zufuzz_result`. |
| `R/fuzz_function.R` | Harness generation for `fuzz_function()`: name resolution, `expect` validation, input adapter. |
| `R/replay.R`, `R/minimize.R` | Run-once replay, fingerprints, the gated reducer and its accelerators. |
| `R/sidecar.R` | Sidecar schema, read/write, environment capture, SHA-1 names via `digest`. |
| `tests/fixtures/fake-engine.R` | The supervisor test double that lets the launcher be tested on CRAN. |
| `fuzz/`, `bench/` | Development harnesses and experiments, build-ignored. |

**`zufuzz.libfuzzer` (r-universe, separate repository):**

| Location | Responsibility |
| --- | --- |
| `src/libfuzzer/` | Vendored libFuzzer file subset, pinned version in `src/libfuzzer/VERSION`. |
| `src/bridge.cpp` | `LLVMFuzzerRunDriver` call, callback, unwind protection, signal reset, error → sidecar → `abort()`, fingerprint gate, region registration, cmp/memcmp/memmem forwarding, custom-mutator delegation. |
| `R/fuzz_libfuzzer.R` | The in-process `fuzz()` method zufuzz dispatches to; wrapper script for re-exec. |
| `inst/preload/` or build step | Preload object for Configuration B and Track N. |

## 16. Open items to verify empirically (not assumptions)

1. The signal reset strategy on Linux and macOS, with and without ASan, against
   the pinned libFuzzer's `SetSigaction` (chains `SIGSEGV`, skips other
   pre-handled signals). `R_NO_SEGV_HANDLER` predates R 4.4 per NEWS; confirm
   it exists at the package minimum R version.
2. Vendored libFuzzer compiles cleanly with R's default flags on Ubuntu (GCC),
   macOS (Apple clang), and R-devel; identify any `-pedantic` noise to silence
   locally rather than by patching sources.
3. `R_UnwindProtect` cost per input; whether `R_tryCatch` alone suffices.
4. Probe cost: `.Call` with an embedded `NativeSymbolInfo` vs alternatives;
   whether JIT compilation of transformed closures changes anything.
5. `-fork`/`-jobs` through the wrapper script, including `--vanilla` vs a
   project `.Rprofile` that the user relies on.
6. Whether libFuzzer's `-rss_limit_mb` thread interacts badly with R's
   allocator or `gctorture`.
7. Dynamic-symbol resolution for sancov callbacks under both sanitized
   configurations (track N).
8. **Vendored libFuzzer builds with GCC.** Static evidence is strong (every
   construct used is a GCC builtin; upstream guards against a GCC warning);
   an actual green build on Ubuntu with the system GCC is not yet in hand. It
   gates the choice of pinned release: companion Stage E0's first CI job.
9. AFL's fork server treats a child that dies of `SIGABRT` raised from R via
   `tools::pskill()` as a crash, in both plain and persistent modes — and
   `AFL_SKIP_BIN_CHECK=1` plus a bitmap zufuzz writes itself satisfies
   `afl-fuzz`'s startup checks in current AFL++ (python-afl proves the
   original AFL; AFL++ added checks since).
10. `R CMD check --as-cran` on all three platforms produces no compiled-code
    NOTE for `zufuzz.so` — i.e. the Stage 0 symbol scan and CRAN's scanner
    agree on what counts as an entry point that might terminate R.
11. `afl-fuzz` on macOS with an R worker: speed, the crash-reporter
    interaction, and whether the deferred fork server survives R's startup.
12. Where CmpLog's `__afl_cmp_map` can be written from a non-afl-cc child, for
    comparison tracing on the AFL++ engine in 0.2.
13. Whether `-minimize_crash`/`afl-tmin` acceleration actually saves time over
    the gated R-side reducer for typical R error findings, or whether the
    accelerators should be dropped for simplicity.
