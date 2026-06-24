Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=opensips

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/opensips/inspector-report/20250411/fuzz_report.html

Opensips is a (Session Initiation Protocol) server, also known as a SIP proxy server, is the central hub in a VoIP system that manages and directs all SIP-based communication, including calls, messages, and video streams, between two or more participants.  SIP servers have many  independent functions, such as: initiation termination, call routing, authentication and encryption, load-balancing, codec negotiation, session management, and many other features.  4 current fuzz drivers only reach a few of the modules and about 13% of the code.

This is a large project with many different independent modules, each with their own readme and functionality. https://github.com/OpenSIPS/opensips/tree/master/modules   A majority of these modules have 0% code coverage.
