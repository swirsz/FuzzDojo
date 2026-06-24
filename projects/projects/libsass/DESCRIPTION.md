Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=libsass

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/libsass/inspector-report/20250411/fuzz_report.html

Libsaas is a C++ port of the original Ruby Sass CSS compiler with a C API.  

This project has 30% total code coverage.  Currently has a single partially broken fuzz driver. There are lots of parsing functions with no code coverage. Likely to need a good CSS dictionary/corpus for effective fuzzing.
