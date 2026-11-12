// Copyright 2019 Google Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// libFuzzer harness for fuzzing snappy's decompression code.

#include <stddef.h>
#include <stdint.h>
#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdlib>
#include <random>
#include <string>
#include <utility>
#include <vector>
#include <cassert>
#include <string>

#include "snappy.h"
#include "snappy-sinksource.h"

struct iovec* GetIOVec(const std::string& input, char*& buf, size_t& num) {
  std::minstd_rand0 rng(input.size());
  std::uniform_int_distribution<size_t> uniform_1_to_10(1, 10);
  num = uniform_1_to_10(rng);
  if (input.size() < num) {
    num = input.size();
  }
  struct iovec* iov = new iovec[num];
  size_t used_so_far = 0;
  std::bernoulli_distribution one_in_five(1.0 / 5);
  for (size_t i = 0; i < num; ++i) {
    assert(used_so_far < input.size());
    iov[i].iov_base = buf + used_so_far;
    if (i == num - 1) {
      iov[i].iov_len = input.size() - used_so_far;
    } else {
      // Randomly choose to insert a 0 byte entry.
      if (one_in_five(rng)) {
        iov[i].iov_len = 0;
      } else {
        std::uniform_int_distribution<size_t> uniform_not_used_so_far(
            0, input.size() - used_so_far - 1);
        iov[i].iov_len = uniform_not_used_so_far(rng);
      }
    }
    used_so_far += iov[i].iov_len;
  }
  return iov;
}

int VerifyIOVecSource(const std::string& input) {
  std::string compressed;
  std::string copy = input;
  char* buf = const_cast<char*>(copy.data());
  size_t num = 0;
  struct iovec* iov = GetIOVec(input, buf, num);
  snappy::CompressFromIOVec(iov, num, &compressed);
  snappy::MaxCompressedLength(input.size());
  snappy::IsValidCompressedBuffer(compressed.data(), compressed.size());

  std::string uncompressed;
  snappy::Uncompress(compressed.data(), compressed.size(), &uncompressed);
  delete[] iov;
  return uncompressed.size();
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string input(reinterpret_cast<const char*>(data), size);

  // Avoid self-crafted decompression bombs.
  size_t uncompressed_size;
  constexpr size_t kMaxUncompressedSize = 1 << 20;
  bool get_uncompressed_length_succeeded = snappy::GetUncompressedLength(
      input.data(), input.size(), &uncompressed_size);
  if (!get_uncompressed_length_succeeded ||
      (uncompressed_size > kMaxUncompressedSize)) {
    return 0;
  }

  std::string uncompressed;
  // The return value of snappy::Uncompress() is ignored because decompression
  // will fail on invalid inputs.
  snappy::Uncompress(input.data(), input.size(), &uncompressed);
  VerifyIOVecSource(input);
  char* buffer = new char[input.size()*5];
  snappy::UncheckedByteArraySink sink(buffer);
  snappy::ByteArraySource source(input.data(), input.size());
  snappy::Uncompress(&source, &sink);
  delete []buffer;
  return 0;
}
