Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=casync

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/casync/inspector-report/20250411/fuzz_report.html

casync is a Content Addressable Data Synchronizer, a tool that combines the rsync algorithm with content addressable storage.

This projects has a single fuzz driver that compresses and decomposes a stream of random data, but only hits 10% of the project code. Many different compression options, such as XZ and LibZ are not called, and none of the utility functions are executed.  The github project page lists a number of operations that could be implemented in fuzz drivers.  https://github.com/systemd/casync