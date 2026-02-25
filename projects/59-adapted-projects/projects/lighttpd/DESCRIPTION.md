Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=lighttpd

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/lighttpd/inspector-report/20250411/fuzz_report.html

Lighttpd is a high-performance Web server.

A single fuzz driver submits urls with random input to the Web server, but many other methods of fuzzing the code are possible.  Access or authentication methods could be used to access the buffer functions that have uncovered complexity for example.
