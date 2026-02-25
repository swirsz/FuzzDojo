Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=sqlite3

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/sqlite3/inspector-report/20250406/fuzz_report.html

Sqlite3 is an open-source relational database written in C.  It has a single fuzz driver that reaches 76% of the code, by parsing random data as SQL statements.  

Unreached sections of code are distributed through a wide number of functions, making targeting these areas fairly difficult.  There appears to be Json parsing, file I/O, and other small miscellaneous sections with some potential.
