Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=astc-encoder

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/astc-encoder/inspector-report/20250520/fuzz_report.html

The arm astc-encoder or Adaptive Scalable Texture Compression (ASTC) Encoder, astcenc, is a command-line tool for compressing and decompressing images using the ASTC texture compression standard.

The encoder has 1 fuzz driver that covers symbolic_to_physical and reaches 50% of the project coverage. A second single function symbolic_to_physical  should reach the majority of the remaining code.
