Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=yara

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/yara/inspector-report/20250411/fuzz_report.html

Yara is a pattern matching tool for malware analysis. It is written primarily in C. 6 fuzz drivers reach 63% of the project code.  Looking at the names of these fuzz drivers shows that they match the names of the modules of the project.  One module, dex, is blocked and only covers 14% of the code, while other modules are covered between 80% to 90%.  Fixing this driver might increase coverage by a thousand lines of code or so.  

Another possible approach would be to create a completely different type of fuzz driver.  The libyara/exec.c file contains a lot of uncovered code, and evaluating complex Boolean expressions seems to be the purpose of many of these functions.
