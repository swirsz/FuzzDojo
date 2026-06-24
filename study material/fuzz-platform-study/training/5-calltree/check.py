#!/usr/bin/env python3
import json
import sys

print("###\n### Improve Coverage Using the Call Tree - bzip2\n###\n")
print("In this challenge, you have a working fuzz driver that could be improved")
print("by calling functions higher in the call tree. The source code of the")
print("current fuzz driver calls 2 different functions: BZ2_bzWrite and")
print("BZ2_bzWriteClose64.  Both can be swapped for similar functions.\n")

print("To browse source code or get hints, you can run an updated fuzz introspector")
print("report or https://introspector.oss-fuzz.com/project-profile?project=bzip2\n")

print("Hint: View the source code of bzlib.c and look for functions that call")
print("BZ2_bzWrite and BZ2_bzWriteClose64. See if you can use these functions")
print("in a fuzz driver, and see what parameters they require.  Only swapping one")
print("function should be required. Both functions should require fewer parameters")
print("than those currently implemented in training-calltree/newfuzzer.c\n")

summary_file = "/out/fuzzer_stats/newfuzzer.json"
returncode = 0
target = 19

try:
    with open(summary_file, "r") as fj:
        content = json.load(fj)
        for dd in content['data']:
            filenames = dd.get('files')
            for files in filenames:
                if files.get('filename') == "/src/bzip2/bzlib.c":
                    func = files['summary']['functions']['covered']
                    print("{0} functions reached. ".format(str(func)))
                    returncode = int(func)
except:
    print("Missing "+summary_file)
    print("\nPlease run /challenge/loc first\n")

exit(returncode)
