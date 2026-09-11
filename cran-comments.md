## R CMD check results

0 errors | 0 warnings | 0 notes

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
