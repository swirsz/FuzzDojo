#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd $SRC/kamailio

export CC_OPT="${CFLAGS}"
export LD_EXTRA_OPTS="${CFLAGS}"

sed -i 's/int main(/int main2(/g' ./src/main.c

export MEMPKG=sys
make Q=verbose || true
cd src
mkdir objects && find . -name "*.o" -exec cp {} ./objects/ \;
ar -r libkamilio.a ./objects/*.o
cd ../

$CC $CFLAGS -c ./misc/fuzz/fuzz_kemi.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_kemi.o -o $OUT/fuzz_kemi \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP

$CC $CFLAGS -c ./misc/fuzz/fuzz_dns.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP -DUSE_DNS_CACHE

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_dns.o -o $OUT/fuzz_dns \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP -DUSE_DNS_CACHE

$CC $CFLAGS -c ./misc/fuzz/ppcfg.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ppcfg.o -o $OUT/ppcfg \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm -DHAVE_GETHOSTBYNAME2 -DUSE_TCP

$CC $CFLAGS -c ./misc/fuzz/rvalue2.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE rvalue2.o -o $OUT/rvalue2 \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS -c ./misc/fuzz/do_action.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE do_action.o -o $OUT/do_action \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS -c ./misc/fuzz/fuzz_udp.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_udp.o -o $OUT/fuzz_udp \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS -c ./misc/fuzz/fuzz_main_parsers.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_main_parsers.o -o $OUT/fuzz_main_parsers \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS -c ./misc/fuzz/fix_actions.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fix_actions.o -o $OUT/fix_actions \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS -c ./misc/fuzz/fuzz_uri.c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_uri.o -o $OUT/fuzz_uri \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CC $CFLAGS  ./misc/fuzz/fuzz_parse_msg.c -c \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse_msg.o -o $OUT/fuzz_parse_msg \
    -DFAST_LOCK -D__CPU_i386 ./src/libkamilio.a \
    -I./src/ -I./src/core/parser -ldl -lresolv -lm

