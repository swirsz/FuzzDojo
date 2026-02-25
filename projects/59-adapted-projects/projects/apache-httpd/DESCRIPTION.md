Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=apache-httpd

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/apache-httpd/inspector-report/20250411/fuzz_report.html

Apache Httpd is one of the most popular and powerful web servers.  It is known for its high compatibility and stability.

Seven different fuzz drivers execute different areas of the code, but the overall code coverage seems very low.  In order to fuzz the sockets directly or to fuzz the modules, additional tools or code changes are usually required. Many online articles have been written about fuzzing Web servers, but it does not look like many of those implementations have made it into OSS-Fuzz.
