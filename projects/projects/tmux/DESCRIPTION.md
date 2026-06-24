Use (Report link) to browse the source code and fuzz introspector report https://introspector.oss-fuzz.com/project-profile?project=tmux

Fuzz Introspector
https://storage.googleapis.com/oss-fuzz-introspector/tmux/inspector-report/20250411/fuzz_report.html

Tmux is a terminal multiplexer written in C.  A single fuzz driver reaches only 14% of the code by fuzzing the input_parse_buffer.  The fuzz blockers highlighted by Fuzz Introspector show large sections of code that could be targetted by new fuzz drivers.  For example: window layout, cmdq_new_state (creates a new state object that represents the context in which commands are executed within tmux), args_parse (string arguments sent to tmux's command system)
