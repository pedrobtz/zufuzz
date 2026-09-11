# zufuzz 0.0.0.9000

* Package foundation (roadmap Stage 0). No user-facing functions yet; the
  native layer registers its routines, reports whether this build can attach
  to an AFL supervisor, and is guarded by a symbol scan asserting that it
  cannot end the R process, signal it, write to its standard streams, or
  reference a fuzzing-engine or sanitizer symbol.
