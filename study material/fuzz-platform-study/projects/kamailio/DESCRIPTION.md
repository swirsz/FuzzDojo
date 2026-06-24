Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=kamailio

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/kamailio/inspector-report/20250411/fuzz_report.html

Kamailio is used by large Internet Service Providers to provide public telephony service as a SIP Server.

It currently uses 2 fairly simple fuzz drivers with 10% total code coverage.   There are many unfuzzed functions with huge unreached code complexity such as "main2" & "yyparse"
