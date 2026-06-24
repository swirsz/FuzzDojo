Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=exiv2

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/exiv2/inspector-report/20250411/fuzz_report.html

Exiv2 is a command line utility to manage image metadata - roughly 60% coverage from a single fuzz driver that does the basic functionality of opening reading and printing image metadata. Lots of source code files appear to have low code coverage. Documentation on https://exiv2.org/doc/index.html gives examples of many features beyond the basic "read exif data" that probably are not implemented by fuzz drivers such as:

Iptcprint is a similar example to print IPTC data. Addmoddel shows how to add, modify and delete Exif metadata. Exifcomment shows how to set the exif comment of an image. Xmpsample.cpp contains examples of how to set various types of XMP properties. For more real-world code have a look at the implementation of the different actions of the Exiv2 utility (actions.cpp).
