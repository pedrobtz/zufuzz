# zufuzz 0.0.0.9000

* `fuzz()` run-once mode, crash artifacts with JSON sidecars, error
  fingerprints, and `replay()` (roadmap Stage 4). Run-once needs no engine,
  returns rather than terminating, and works on every platform — it is what
  `replay()` and coverage reporting are built on.
* `instrument()`, `instrument_package()`, `instrument_all()`,
  `instrumentation_report()` and `uninstrument()` (roadmap Stage 3) — the
  first user-facing functions. Rewrites a closure's body so reaching a branch
  records a hit, preserving value, visibility, laziness, evaluation order,
  error propagation, `return`/`break`/`next` and `on.exit`.
* Instrumentation planning (roadmap Stage 2): the AST walk that decides where
  probes go, selection resolution over namespaces and S3 method tables, and a
  manifest digest. Pure R, and it changes nothing — Stage 3 executes a plan.
  Still internal.
* Coverage counter region with its three sink modes (roadmap Stage 1), and
  the `R_RegisterCCallable()` interface the companion engine package uses to
  reach it. Still internal: no user-facing functions yet.

* Package foundation (roadmap Stage 0). No user-facing functions yet; the
  native layer registers its routines, reports whether this build can attach
  to an AFL supervisor, and is guarded by a symbol scan asserting that it
  cannot end the R process, signal it, write to its standard streams, or
  reference a fuzzing-engine or sanitizer symbol.
