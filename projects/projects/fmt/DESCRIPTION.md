Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=fmt

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/fmt/inspector-report/20250411/fuzz_report.html

{fmt} is an open-source formatting library providing a fast and safe alternative to C stdio and C++ iostreams.

7 fuzz drivers cover 80% of the project code, which is composed of hundreds of mostly independent functions. There are still a few uncovered functions, such as copy_fill_from, constexpr auto count(), write_codecvt, do_write, write, operator functions, and many more.
