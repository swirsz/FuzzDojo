Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=arduinojson 

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/arduinojson/inspector-report/20250411/fuzz_report.html

ArduinoJson is a C++ JSON library

Fuzz introspective reports that it has 99.51% static reachability, but only 49% actual coverage is being reached by the 2 existing fuzz drivers.

Plenty of functions in the code coverage report show 0% coverage, and these would be ideal to call with a new fuzz driver.
