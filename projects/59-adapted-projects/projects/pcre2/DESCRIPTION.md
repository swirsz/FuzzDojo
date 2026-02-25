Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=pcre2

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/pcre2/inspector-report/20250411/fuzz_report.html

The PCRE2 library is a set of C functions that implement regular expression pattern matching.  9 fuzz drivers reach 70% of the code, which comprises of 96% of the cyclomatic complexity of the project.

Only a few specialty functions such as recursive arguments, shifting, and byte manipulations has the potential for increased code coverage.
