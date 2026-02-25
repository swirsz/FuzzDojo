Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=openjpeg

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/openjpeg/inspector-report/20240911/fuzz_report.html

https://storage.googleapis.com/oss-fuzz-introspector/openjpeg/inspector-report/20250411/fuzz_report.html

OpenJPEG is an open-source JPEG 2000 codec written in C language.  It consists of two libraries, one for implementing JPEG 2000 files and also a client/server architecture for remote browsing of JPEG 2000 images known as jpip.  The project reached 52% code coverage in 2024 with 2 fuzz drivers, one fuzz driver for each library, however a more recent change has broken the code coverage details of the project.

This project is highly dependent on corpus data to exercise functionality.   Important functions in j2k.c and jp2.c are not currently being covered, such as comparisons and encoding functions. A tests folder contains many operations that are not currently implemented as fuzz drivers.
