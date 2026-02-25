Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=elfutils

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/elfutils/inspector-report/20250411/fuzz_report.html

Elfutils is a collection of utilities and libraries to read, create and modify ELF binary files, find and handle DWARF debug data, symbols, thread state and stacktraces for processes and core files on GNU/Linux.

This project has low code coverage, only three fuzz drivers, many of these utilities/libraries are not fuzzed: for example multiple disassemblers have 0% code coverage.
