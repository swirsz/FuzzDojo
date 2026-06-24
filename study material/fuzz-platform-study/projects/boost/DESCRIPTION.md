Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=boost

Boost is a very large collection of portable C++.  14 fuzz drivers currently exercise about half of the code in the project.

Browsing the code coverage report shows that some libraries have high coverage and other libraries have almost no coverage.  For example, the file system fuzz driver has about 15 simple calls to file system functions, executing only about 7% of the code in the /filesystem  folder, but hundreds and hundreds of addressable file system functions are completely untouched.
