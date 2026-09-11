# zufuzz: coverage-guided fuzzing for R, in the style of Atheris and Ruzzy

**Status:** design, second revision, 2026-09-11. Nothing below is implemented.
**Companion:** [roadmap.md](roadmap.md) (stages, gates, and completion criteria).

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

Both reference projects share one architecture, which this design adopts:

```text
harness script (Python / Ruby / R)
  |
  |  test_one_input(bytes)             <- user code, in-process
  v
bridge extension (atheris.so / cruzzy.so / zufuzz.so)
  |  - links libFuzzer statically and calls LLVMFuzzerRunDriver()
  |  - owns an 8-bit counter region registered with libFuzzer
  |  - instruments interpreted code so probes bump those counters
  |  - forwards comparisons to libFuzzer's trace-cmp / memcmp hooks
  |  - turns an uncaught interpreter exception into a crash artifact
  v
libFuzzer: corpus, mutation, scheduling, -dict, -timeout, -rss_limit_mb,
           -jobs/-fork, -merge, -minimize_crash, crash-/timeout-/oom- artifacts
  |
  v
native extensions built with ASan/UBSan (+ -fsanitize=fuzzer-no-link for
native coverage), detected by the sanitizer runtime, saved by libFuzzer
```

The important consequence: **zufuzz implements no mutator, no corpus store, no
scheduler, no per-input IPC protocol, and no timeout supervisor.** It implements
the bridge, the R instrumentation, the R-side data provider, and the R-side
reproduction tooling. That is also what Atheris and Ruzzy implement.

How those pieces are layered inside the package — which parts are C, which are
R, and which work without the engine — is §15.

### Feature parity target

Cells reflect each project's public README at time of writing; verify before
quoting externally.

| Capability | Atheris | Ruzzy | zufuzz 0.1 | zufuzz later |
| --- | --- | --- | --- | --- |
| libFuzzer engine, flags, corpus dirs, `-dict`, artifacts | yes | yes | yes | |
| Interpreted-code coverage feedback | bytecode rewriting | Ruby `TracePoint` | R AST rewriting → 8-bit counters | |
| Comparison tracing for interpreted code (solves magic bytes) | yes (bytecode `COMPARE_OP` tracing; not prominent in its README) | — | yes (`==`, `identical`, `%in%`, `startsWith`, `switch`, fixed `grepl`) | regex hooks |
| `FuzzedDataProvider` | yes | yes | yes | |
| Native extensions under ASan/UBSan | yes (Clang, preload) | yes (Clang, preload) | documented configurations + preload helper | `sanitizer_build()` |
| Native coverage (`-fsanitize=fuzzer-no-link`) | yes | yes | feasibility track N | supported |
| Custom mutator / crossover | yes | — | bridge exports the hooks | R-level API |
| `-jobs`, `-fork`, `-merge`, `-minimize_crash` | not documented | not documented | libFuzzer via re-exec wrapper (**unproven — Stage 1 gate**) | |
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
| Windows | no | Docker only | package installs; engine unavailable | |

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
the wrapper-script approach should work — but it is unverified, and Stage 1
does not complete until `-fork`, `-jobs`, and `-minimize_crash` all re-exec
correctly. If they cannot, drop the claim rather than shipping it.

## 1. What changed from the first revision, and why

| First revision | This revision | Reason |
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

What did **not** change: the conservative AST transformation rules, the
`substitute()` hazard analysis, the harness oracle rules, the three reproduction
guarantees, the conservative fingerprint, the raw-bytes-first rule for text, the
benchmark discipline, and the gate mindset.

## 2. Product boundary

### 0.1.0 includes

- `fuzz()`: run libFuzzer in-process over an R `test_one_input(data)` closure,
  with full libFuzzer flag passthrough.
- `instrument()` / `instrument_package(recursive =)` / `instrument_all()`:
  R coverage feedback via AST rewriting into a libFuzzer counter region, plus
  comparison tracing.
- `fuzz(coverage_out =)`: a `covr`-compatible report of what a campaign reached.
- `fuzzed_data_provider()`: deterministic structured consumption of raw bytes.
- `r_object()` / `$consume_object()` / `draw()` / `as_seed()` / `object_from()`:
  byte-driven R object generation at `strict` and `nasty` levels, usable in a
  campaign and in an interactive session.
- Uncaught R error → diagnostic on stderr, JSON sidecar, `crash-<sha1>` artifact.
- R-level hangs and memory growth caught by libFuzzer `-timeout` / `-rss_limit_mb`.
- `fuzz_file()`: launcher that runs a harness script under `Rscript`, parses
  libFuzzer output, and returns a `zufuzz_result` (for CI and in-session use).
- `replay()`: fresh-process, uninstrumented execution of an artifact through the
  same harness, with structured outcome and environment-mismatch reporting.
- `minimize()`: libFuzzer crash minimization gated on the original finding's
  fingerprint.
- Optional per-input RNG reset and GC torture.
- Documented sanitizer configurations for Linux (§10), including a preload
  helper, without a build wrapper yet.
- Linux and macOS engine support; Windows installs with the engine disabled.

### 0.1.0 excludes

Native coverage feedback as a supported feature (track N decides), the
`adversarial` validity level (needs its triage policy proven first),
`sanitizer_build()`,
an R-level custom mutator API (the C hooks exist), regex hooks, corpus merge
helpers beyond documenting `-merge=1`, S4/R6/RC method instrumentation, a CRAN
submission (see §13), and any claim of Windows fuzzing.

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
Rscript fuzz/parse_json.R crash-3f2a...        # a file argument = run it once and exit (libFuzzer behavior)
Rscript fuzz/parse_json.R -jobs=4 -fork=4 fuzz/corpus/parse_json
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
  ...,                                  # libFuzzer flags as named args: max_len = 4096, dict = "x.dict"
  before_each = NULL,                   # zero-arg closure, run before each input, uncounted
  rng_seed = NULL,                      # integer: restore this R RNG state before each input
  gc_torture = FALSE,                   # TRUE or an integer step for gctorture2()
  artifact_dir = NULL,                  # default ".zufuzz/artifacts/"; sets -artifact_prefix
  coverage_out = NULL,                  # dump hit sites at exit; covr-compatible JSON
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

fuzz_file(path, corpus = NULL, args = character(), ...,
          time_limit = Inf, runs = Inf, artifact_dir = NULL, env = character(), quiet = FALSE)
fuzz_function(fn, corpus = NULL, ..., input = c("raw", "string"),
              expect = character(), instrument = NULL, harness_out = NULL)
replay(path, input, ..., instrument = FALSE)
minimize(path, finding, out, runs = 1000, ...)

preload_path()                          # path of the libFuzzer(+ASan) preload object, see §10
```

Flags: `args` is passed to libFuzzer verbatim after zufuzz's own defaults;
named `...` become `-name=value` and are appended after `args`, so explicit R
arguments win. Positional entries (no leading `-`) are corpus directories or
input files, exactly as in libFuzzer. zufuzz sets these defaults unless
overridden: `-artifact_prefix=.zufuzz/artifacts/`, `-print_final_stats=1`,
`-timeout=25` (libFuzzer's 1200 s default is unhelpful for R targets).

**`fuzz()` never returns.** libFuzzer's driver ends every mode with `exit()`:
exit 0 when `-runs`/`-max_total_time` is exhausted or after replaying listed
files, `-error_exitcode` (77) on a finding, `-timeout_exitcode` (70) on a
timeout. This is the same contract as `atheris.Fuzz()` ("does not return").
`fuzz_file()` exists for callers who want a value.

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

Validation before the driver starts: `test_one_input` is a closure of one
argument; no nested `fuzz()` (an env marker is set for the process); flags with
unsupported values are rejected by libFuzzer itself. `fuzz()` refuses to run
when `interactive()` is true, because it would terminate the session; use
`fuzz_file()` there.

## 4. Execution model: the bridge

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
engine or API is needed.

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

- One `uint8_t` region per process, sized from the frozen plan, registered
  once with `__sanitizer_cov_8bit_counters_init(start, end)` and a matching
  synthetic table via `__sanitizer_cov_pcs_init` (libFuzzer wants both; Atheris
  does the same). Probes increment `region[site]` — no `.Call` allocation, no
  clearing: libFuzzer reads and zeroes counters per input.
- Site identity = (function identity, AST position) in deterministic
  enumeration order (sorted binding names, pre-order walk). Source references
  are display metadata. The manifest digest covers instrumentation version,
  selection, and original body digests, and is recorded in sidecars so
  `-fork`/`-jobs` children can be checked for agreement.
- Hit counts, not presence: libFuzzer buckets counter values, so loop trip
  counts become features for free.
- Nothing is cached across processes: libFuzzer re-executes the corpus at
  startup; a corpus from an older manifest is simply re-run.
- `coverage_out` dumps the accumulated hit set against the site map at process
  exit (an `atexit` handler in the bridge, since `fuzz()` never returns),
  answering "what did this campaign actually reach". Atheris does the same
  through `-atheris_runs` plus `coverage.py`; the R output is shaped for
  `covr`, so existing reporting tools apply. It is a report, not feedback:
  counts come from libFuzzer's buckets and are not a statement about
  correctness.

## 7. Mutation, scheduling, dictionaries

All libFuzzer. Users pass `-dict=file` in libFuzzer/AFL dictionary syntax,
`-max_len`, `-len_control`, `-use_value_profile=1`, `-only_ascii=1`, `-seed`.
`fuzz(dictionary = list(raw, ...))` is sugar that writes a temporary
dictionary file. The custom-mutator hooks are exported by the bridge and
delegate to `LLVMFuzzerMutate` until an R API exists (0.2).

## 8. Corpus, artifacts, metadata

Layout (libFuzzer conventions plus sidecars):

```text
fuzz/
  parse_json.R
  corpus/parse_json/<sha1>            # libFuzzer-managed, bytes only
  json.dict
.zufuzz/
  artifacts/
    crash-<sha1>                      # written by libFuzzer
    crash-<sha1>.json                 # written by the bridge before abort()  (R errors only)
    crash-<sha1>.log                  # stderr captured by fuzz_file()/replay()
    timeout-<sha1>, oom-<sha1>        # libFuzzer; sidecar written by the launcher from the log
  runs/<run-id>.json                  # fuzz_file() campaign record
  bin/<harness-sha1>.sh               # re-exec wrapper
tests/testthat/fixtures/fuzz/issue-17.bin
```

Sidecar contents: schema version, artifact SHA-1 and length, outcome kind,
condition classes, message, normalized originating call, traceback (bounded,
truncation marked), fingerprint, harness path and digest, instrumentation
manifest digest and JIT level, `rng_seed`, R version, platform, loaded package
versions and library paths, locale, and the libFuzzer flags. Not the whole
process environment (credentials). Native findings have no R-side sidecar at
crash time; `fuzz_file()` and `replay()` derive one from the sanitizer report
in the log.

The bridge computes the SHA-1 with the vendored `FuzzerSHA1.cpp` so the sidecar
name matches libFuzzer's artifact name.

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

`minimize(path, finding, out, runs)` runs
`Rscript path -minimize_crash=1 -runs=<runs> -exact_artifact_path=<out> <finding>`
with `ZUFUZZ_EXPECT_FINGERPRINT=<fp>`. Under that variable the bridge aborts
only when the escaped error's fingerprint matches; any other error returns
normally and libFuzzer therefore rejects the candidate. This keeps libFuzzer's
minimizer from silently switching bugs. Refuse to minimize unconfirmed
findings, timeouts, and findings whose fingerprint fields were truncated. The
original artifact is never modified.

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
needs `use_sigaltstack=0` once `R_NO_SEGV_HANDLER` is set is a Stage 11 test.
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

1. If `zufuzz.so` (which contains libFuzzer) is loaded `RTLD_LOCAL`, a target
   package loaded afterwards cannot resolve the callbacks from it at all.
   zufuzz must load its DLL with `library.dynam(..., local = FALSE)`.
2. Even then, in Configuration A the ASan runtime is a dependency of the R
   executable and in Configuration B it is preloaded — in both cases it sits
   *before* `zufuzz.so` in search order, so the target's callbacks bind to
   ASan's definitions and libFuzzer silently sees no native coverage.
3. ASan's `memcmp`/`strcmp` interceptors call `__sanitizer_weak_hook_memcmp`
   etc. only if those weak references resolved when ASan loaded; a libFuzzer
   loaded later is invisible to them.

Atheris solves all three by preloading one object that contains libFuzzer and
links the ASan runtime, so libFuzzer's definitions come first. zufuzz needs
the same: a `zufuzz_preload.so` built alongside `zufuzz.so` (libFuzzer +
bridge glue, linked with `-fsanitize=address` when a sanitizer configuration
is requested), returned by `preload_path()`. In Configuration A the preload
still comes before the executable's dependencies, so it works there too.

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
  by R's own checks as R errors, which the bridge already reports.
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

| Platform | Engine (R-only coverage) | ASan/UBSan targets | Native coverage |
| --- | --- | --- | --- |
| Linux, GCC or Clang | supported | Configuration A or B | Track N (Clang) |
| macOS, Apple clang | supported | needs validation (`DYLD_INSERT_LIBRARIES`, SIP) | unlikely without LLVM clang |
| Windows | replay-only | no | no |

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

The staging is: **0.1** — the bridge catches native crashes, Configurations A
and B are documented, `preload_path()` and sidecars-from-logs ship, and the
Docker image is the reference environment (roadmap Stage 11). **Track N** —
the native coverage experiment and its decision. **0.2** —
`sanitizer_build()`, native coverage if Track N passed, macOS validation.

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

`fuzz_file()` runs `Rscript --vanilla <harness> <corpus> <args>` under
`processx`, streams stderr to a log, applies `time_limit`/`runs` as
`-max_total_time`/`-runs`, and classifies the exit:

| Evidence | `stop_reason` |
| --- | --- |
| exit 0 (budget exhausted, or listed files replayed) | `budget` |
| libFuzzer error exit code, `crash-` artifact | `finding` |
| timeout exit code, `timeout-` artifact | `finding` (kind `timeout`) |
| `oom-` artifact | `finding` (kind `oom`) |
| interrupted | `interrupted` |
| anything else (harness failed to load, missing package, bad flag) | `infrastructure` |

`zufuzz_result` fields: `stop_reason`, `finding` (artifact, sidecar,
fingerprint, kind), `executions`, `exec_per_sec`, `new_units_added`,
`peak_rss_mb`, `corpus_dir`, `log`, `elapsed`, libFuzzer's final stats verbatim.
`print()` never labels feature counts "paths". Findings are a distinct stop
reason so CI cannot mistake one for success.

CI layers:

1. Ordinary `testthat` replays committed regression fixtures with base R.
2. A separate smoke workflow runs `fuzz_file()` with fixed `-runs` and `-seed`
   and fails on `finding` or `infrastructure`.
3. Scheduled campaigns persist the corpus and upload artifacts and logs.

Long campaigns never run as examples or in `R CMD check`.

## 13. Packaging constraints

- libFuzzer is vendored under `src/libfuzzer/` from a pinned LLVM release
  (Apache-2.0 WITH LLVM-exception; record it in `LICENSE.note`/`inst/COPYRIGHTS`
  and `Authors@R` `cph`). It builds with GCC or Clang, C++17, no LLVM at
  install time. Precedent: `libfuzzer-sys`.
- `Makevars` compiles the bridge and libFuzzer on Linux/macOS. `Makevars.win`
  defines `ZUFUZZ_NO_LIBFUZZER`; `fuzz()` then supports only the "run these
  files once" mode so regression replay works on Windows, and errors otherwise.
- `R CMD check` will NOTE that compiled code calls `abort`, `exit`, and writes
  to stderr. That is the package's purpose. **CRAN is not a 0.1.0 target**;
  distribution is GitHub and r-universe. Revisit CRAN only with a plan for the
  NOTE and for Windows.
- Minimum R 4.1 (for `R_UnwindProtect`/`R_tryCatch` and C++17 defaults).
- Imports: `processx` (launcher), `jsonlite` (sidecars). No `callr`.

## 14. Validation and gates

Correctness tests use deterministic fixtures; stochastic discovery lives in
`bench/`. Required evidence:

| Area | Evidence |
| --- | --- |
| Bridge | R error → `crash-` artifact + sidecar + error exit; native segfault fixture → `crash-` artifact (with R's handlers reset); R `repeat {}` and native busy loop → `timeout-` artifact; Ctrl-C → clean stop; `-fork`, `-jobs`, `-minimize_crash` re-exec works; no R `longjmp` escapes the callback (run a harness that errors 10 000 times under `-fork=1 -ignore_crashes=1`). |
| Instrumentation semantics | Original vs transformed agree on value, visibility, side effects, laziness, conditions, control transfers; fixtures include missing args, empty bodies, recursion, `on.exit`, byte-compiled input, S3 methods via the table. |
| Feedback | Counters reach libFuzzer ("Loaded 1 modules (N counters)"); nested-prefix fixture solved; magic-string fixture solved via cmp hooks within a fixed `-runs`; the same fixtures are *not* solved by the unguided baseline in that budget. |
| Provider | Every method on empty input, one byte, and boundary ranges; the consumption algorithm matches its written spec byte for byte. |
| Reproduction | Deterministic error fixture confirms via `replay()`; history-dependent fixture reported as unconfirmed; fingerprint stable across processes. |
| Minimization | Reducible fixture shrinks and reconfirms; a candidate that changes the error is rejected; original untouched. |
| Launcher | Each `stop_reason` from a fixture; interrupt cleans up the child. |

Gates (details in the roadmap): **A** — bridge viable in R (signals, unwind,
artifacts, timeouts); **B** — trustworthy R feedback (semantics, counters,
comparison tracing); **C** — measured usefulness (guided vs unguided, ≥ 30
predeclared seeds, equal-attempt and equal-wall-time, on branch-heavy R code
and a representative package); **N** — native coverage feasibility.

Benchmarks: empty target, branch-heavy R target, thin `.Call` wrapper, one real
package. Separate probe overhead, provider overhead, and per-execution bridge
overhead. Report OS, R/compiler versions, hardware, flags, and seeds. Report
time-to-finding over all runs, not only successful ones.

## 15. Architecture and implementation map

### Four layers, one direction of dependency

```text
            R layer  (R/)                        depends on
 ---------------------------------------------------------------------------
  fuzz.R           fuzz()                     -> bridge.cpp -> libfuzzer/
  instrument.R     instrument*()              -> plants .Call into counters.c
  fdp.R objects.R  draw(), r_object(), FDP    -> fdp.c                  ONLY
  launcher.R       fuzz_file(), fuzz_function()
  replay.R         replay(), minimize()       -> processx (no native at all)
 ---------------------------------------------------------------------------
          native layer  (src/)
 ---------------------------------------------------------------------------
  bridge.cpp   driver call, callback, unwind, signal reset, sidecar, abort
  counters.c   counter region, probe hit routine, cmp/memcmp/memmem hooks
  fdp.c        byte cursor + primitive decoding      <- no engine dependency
  libfuzzer/   vendored, pinned                      <- depended on by bridge only
```

Arrows never point upward and never point sideways into `libfuzzer/` except
from `bridge.cpp`. That is what makes the value layer usable on its own.

### Two entry paths

```text
 in-process (a campaign)                out-of-process (interactive, CI)
 ------------------------               --------------------------------
 Rscript harness.R corpus/              fuzz_file() / fuzz_function()
   instrument_package()                 replay() / minimize()
   fuzz(test_one_input)                   |
     |                                    | processx
     v                                    v
   LLVMFuzzerRunDriver  ---- never      Rscript --vanilla harness.R ...
     |                     returns        |
     v                                    v
   callback -> R closure                exit code + artifacts + log
     |                                    |
     v                                    v
   abort() -> crash-<sha1>              zufuzz_result
```

`fuzz()` ends the process; everything a user calls from a live session goes
through the right-hand column. The value layer (below) belongs to neither and
runs anywhere.

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
bottleneck. That split is provisional: Stage 13 measures it, and assembly moves
to C only if the benchmark says so.

### What each export actually needs

| Export | Native code | libFuzzer | Usable in a live session | Windows |
| --- | --- | --- | --- | --- |
| `r_object()` | none (a spec object) | no | yes | yes |
| `fuzzed_data_provider()` | `fdp.c` | no | yes | yes |
| `draw()`, `as_seed()`, `object_from()` | `fdp.c` | no | yes | yes |
| `instrument()`, `instrument_package()`, `instrumentation_report()` | plants probes calling `counters.c` | no | yes (inert without a campaign) | yes |
| `fuzz()` | `bridge.cpp` | **yes** | **no — exits the process** | no |
| `fuzz_file()`, `fuzz_function()`, `minimize()` | none in the caller | in the child | yes | no |
| `replay()` | none in the caller | in the child | yes | yes (replay is the one supported Windows mode) |
| `preload_path()` | none | no | yes | no |

Two consequences worth stating plainly: the generator and provider work on
Windows and in any interactive session even though the engine does not; and
nothing a user calls interactively can take the session down with it, because
the only export that calls `LLVMFuzzerRunDriver` refuses to run when
`interactive()` is true.

### File responsibilities

| Location | Responsibility |
| --- | --- |
| `src/libfuzzer/` | Vendored libFuzzer, pinned version noted in `src/libfuzzer/VERSION`. |
| `src/bridge.cpp` | `LLVMFuzzerRunDriver` call, callback, unwind protection, signal reset, error → sidecar → abort, fingerprint gate, custom-mutator delegation. |
| `src/counters.c` | Counter region allocation and registration, probe hit routine, cmp/memcmp/memmem forwarding. |
| `src/fdp.c` | Provider cursor and consumption algorithm, including object generation. |
| `R/objects.R` | `r_object()` spec, assembly, validity levels, `draw()`, `as_seed()`, `object_from()`. |
| `src/init.c` | Routine registration; `library.dynam(local = FALSE)` policy documented here. |
| `R/fuzz.R` | `fuzz()`, argument/flag handling, wrapper script, RNG and GC torture. |
| `R/instrument.R` | Planning, transformation, comparison rewriting, binding replacement, report. |
| `R/fdp.R` | R face of the provider. |
| `R/launcher.R` | `fuzz_file()`, output parsing, `zufuzz_result`. |
| `R/fuzz_function.R` | Harness generation for `fuzz_function()`: name resolution, `expect` validation, input adapter. |
| `R/replay.R`, `R/minimize.R` | Fresh-process replay, fingerprints, fingerprint-gated minimization. |
| `R/sidecar.R` | Sidecar schema, read/write, environment capture. |
| `inst/preload/` or build step | Preload object for sanitized configurations (track N). |
| `fuzz/`, `bench/` | Development harnesses and experiments, build-ignored. |

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
