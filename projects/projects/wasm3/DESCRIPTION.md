Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=wasm3

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/wasm3/inspector-report/20250411/fuzz_report.html

Wasm3 is a WebAssembly interpreter and the most universal WASM runtime.  It has a single fuzz driver reaching 67% of the code.  This fuzz driver parses and executes code, but other functionality of the project is not addressed.  For example, the m3_exec source code is not well covered, suggesting that since this function handles the interpreter's execution loop and instruction handlers, a fuzz driver generating more valid instructions might exercise this code.   Valid instructions that are not being executed include stack operations, arithmetic operations, memory operations, comparison operations, direct and indirect function calls.
