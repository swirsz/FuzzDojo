Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=xvid

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/xvid/inspector-report/20240921/fuzz_report.html

XVid is a video codec life for the mpeg-4 standard.  The source code repository is no longer accessible online so it is broken on oss-fuzz, but the source code files are still available here and the project compiles and works properly.  A single fuzz driver reaches 33% of the project code.

One approach would be to simply repair this project implementation in OSS-Fuzz by determining what happened in 2024 to break the project's build.   The single fuzz driver only tests decoding functionality and covers up code very completely as shown by the green section in the call graph. Additional fuzz drivers could be written to  address encoding features of the library, or general functionality such as metadata handling, stream management, and bitstream handling functionality.
