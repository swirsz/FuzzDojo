Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=c-ares

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/c-ares/inspector-report/20250411/fuzz_report.html

C-Ares is a C library for asynchronous DNS requests.  It has two simple fuzz drivers, one that validates URLs, and a legacy fuzz driver that providea sample code to execute many different parsing functions.  This is is not useful today since all of these parsing functions have been simplified into a single function.

Only 1/3 of the code is currently being hit by sending simple random parsing requests. Fuzz drivers designed to exercise the specific features of this  library  may be able to hit additional source code. https://github.com/c-ares/c-ares/blob/main/FEATURES.md

Implementing a simplified custom DNS parser also may also do a better job than sending simple random requests.
