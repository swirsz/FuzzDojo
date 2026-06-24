Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=json

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/json/inspector-report/20250411/fuzz_report.html

JSON is a single file json.hpp implementation of a json parser.

With 6 drivers achieving 74% coverage, it seems to have small sections of code that could be exercised by additional fuzz drivers, or additional corpus data. For example there are untouched functions like scan_comment(), start_object() 
