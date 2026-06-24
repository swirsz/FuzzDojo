Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=libsodium
       
Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/libsodium/inspector-report/20250411/fuzz_report.html

LibSodium is an easy-to-use software library for encryption, decryption, signatures, password hashing, and more. 

This library has roughly 20% code coverage with only 2 fuzz drivers, exercising the encryption, decryption, and maybe hashing functions and very little else.  Just implementing ED25519 key signatures as a fuzz driver should greatly increase the code coverage of the project