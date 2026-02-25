Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=w3m

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/w3m/inspector-report/20250411/fuzz_report.html

w3m converts www to text, can also be used as a textmode web browser.  It has a single fuzz driver reaching 70% of the project code.  

Several conversion functions, such as from iso2022 and utf8 have significant uncovered code.
