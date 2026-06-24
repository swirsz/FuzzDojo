Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=aspell

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/aspell/inspector-report/20250519/fuzz_report.html

GNU Aspell is a Free and Open Source spell checker.

A single fuzz driver reaches 75% of the project's code.  The driver hits most of the core features of the program.  Checking through the manual http://aspell.net/man-html/index.html and compare the command-line options with the uncovered functions such as "to_soundslike", dictionary functions, and so on.
