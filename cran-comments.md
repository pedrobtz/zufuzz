## R CMD check results

0 errors | 0 warnings | 1 note

```
checking R code for possible problems ... NOTE
  Found the following possibly unsafe calls:
  File 'zufuzz/R/instrument.R':
    unlockBinding(name, env)
```

This one is inherent to what the package does, and is left visible on
purpose. zufuzz instruments R code for coverage-guided fuzzing, which means
rewriting a function's body and putting it back where it came from; namespace
bindings are locked, so unlocking is the mechanism. The same call appears in
other instrumentation and mocking packages for the same reason.

It is used narrowly: only on a binding that was already locked, only to
replace an existing binding (never to add one), and the lock is restored via
`on.exit()` so a failure part-way cannot leave a namespace writable.
`uninstrument()` puts every original back, and the undo record is written as
each binding is replaced rather than at the end, so an error mid-package is
still fully reversible.

We considered routing the call through `get("unlockBinding", baseenv())` to
avoid the note and decided against it: the note exists to tell you the package
does binding surgery, and it does.

The other note is `checking CRAN incoming feasibility`, reporting a new
submission and that `0.0.0.9000` "contains large components". That is the
development version; a release will carry a normal three-component version.

## Notes for the reviewer

zufuzz drives external fuzzing engines. The package itself contains no
engine: its compiled code is plain C against R's API, and a test in the
package asserts that the shared object references no symbol that could end
the R process, signal it, write to its standard streams, or belong to a
fuzzing engine or sanitizer. There should therefore be no "compiled code
calls ..." NOTE.

Engines are optional and external, declared in `SystemRequirements`. The
package installs, loads, and checks with none of them present, which is the
configuration checked on all platforms. No test or example starts a fuzzing
campaign, downloads anything, or writes outside `tempdir()`.
