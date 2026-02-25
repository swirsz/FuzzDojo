#!/bin/bash

set -e

if [ -z "$OUT" ]; then # POSIX-safe; -z STRING means "true if STRING has length zero".
    echo "OUT env var not defined"
    exit 1
fi

SRC_DIR="/src-orig"
ORIG_DIR="$(pwd)"

# All fuzz targets that should get a seed corpus
FUZZERS=(
  "opj_decompress_fuzzer_J2K"
  "opj_decompress_fuzzer_JP2"
  "GPT5_fuzzer"
)

########################################
# 1) Conformance inputs (jp2/j2k)
########################################
cd "$SRC_DIR/data/input/conformance"

for fuzzer in "${FUZZERS[@]}"; do
    SEED_ZIP="$OUT/${fuzzer}_seed_corpus.zip"

    # Start fresh for each fuzzer
    rm -f "$SEED_ZIP"

    # Add conformance jp2/j2k files (if any). Ignore "no matches" errors.
    zip "$SEED_ZIP" ./*.jp2 ./*.j2k
done

########################################
# 2) Non-regression HTJ2K inputs (j2k/jhc/jph)
########################################
cd "$SRC_DIR/data/input/nonregression/htj2k"

for fuzzer in "${FUZZERS[@]}"; do
    SEED_ZIP="$OUT/${fuzzer}_seed_corpus.zip"

    # We call zip on the same zip file. zip doesn't recreate the archive; it adds these files to the existing zip (or creates it if it doesn't exist yet).
    zip "$SEED_ZIP" ./*.j2k ./*.jhc ./*.jph 2>/dev/null || true
done

# Go back to original directory
cd "$ORIG_DIR"