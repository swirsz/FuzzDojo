Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=alembic

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/alembic/inspector-report/20250514/fuzz_report.html

Alembic is an open framework for storing and sharing scene data that includes a C++ library, a file format, and client plugins and applications.

Alembic has only a single fuzz driver that is shown as blocked by static analysis, reaching almost no code at all.  Dynamic analysis shows 10% coverage, with lots of potential for new fuzz drivers.
