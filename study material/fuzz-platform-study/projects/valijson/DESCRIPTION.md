Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=valijson

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/valijson/inspector-report/20250411/fuzz_report.html

Valijson is a C++ library for JSON Schema validation, with support for many popular parsers.  It has a single fuzz driver reaching 72% of the code.

The validation_visitor.hpp shows many sections of code that are not be exercised. These include date and time matching, integer and double constraint checking, and other regex functions.