Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=miniz

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/miniz/inspector-report/20250411/fuzz_report.html

Miniz is a lossless, high performance data compression library in a single source file that implements the zlib (RFC 1950) and Deflate (RFC 1951) compressed data format specification standards.  Miniz also contains simple to use functions for writing .PNG format image files and reading/writing/appending .ZIP format archives.  It has 9 different fuzz drivers reaching 60% of the code.

A number of validation functions, validating file archives, validating archives in memory, and archive appending features are not currently tested.  This project has an examples folder which might provide additional functionality not currently implemented into fuzz drivers.
