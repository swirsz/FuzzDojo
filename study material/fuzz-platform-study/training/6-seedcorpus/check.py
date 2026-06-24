#!/usr/bin/env python3
import json
import sys

summary_file = "/out/fuzzer_stats/bzip2_decompress_target.json"
returncode = 0
try:
    with open(summary_file, "r") as fj:
        content = json.load(fj)
        for dd in content['data']:
            filenames = dd.get('files')
            for files in filenames:
                if files.get('filename') == "/src/bzip2_decompress_target.c":
                    func = files['summary']['branches']['covered']
                    print("{0} of 2 branches of /src/bzip2_decompress_target.c reached.".format(str(func)))
                    returncode = int(func)
except:
    print("Missing "+summary_file)
    print("\nPlease run /challenge/loc first\n")

exit(returncode)
