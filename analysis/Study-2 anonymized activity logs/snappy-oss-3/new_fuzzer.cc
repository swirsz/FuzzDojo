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
// libFuzzer harness for fuzzing snappy iovec-based compression and decompression.

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

#include "snappy.h"

namespace {

// Maximum number of iovec entries to use in fuzzing
constexpr size_t kMaxIOVecEntries = 32;
// Maximum size for total data to avoid excessive memory usage
constexpr size_t kMaxTotalSize = 1 << 20; // 1MB

// FuzzedDataProvider-like functionality for extracting data from fuzz input
class DataExtractor {
 public:
  DataExtractor(const uint8_t* data, size_t size)
      : data_(data), size_(size), offset_(0) {}

  // Extract a single byte, return 0 if no more data available
  uint8_t ConsumeByte() {
    if (offset_ >= size_) return 0;
    return data_[offset_++];
  }

  // Extract up to max_size bytes
  std::vector<uint8_t> ConsumeBytes(size_t max_size) {
    size_t to_consume = std::min(max_size, size_ - offset_);
    std::vector<uint8_t> result(data_ + offset_, data_ + offset_ + to_consume);
    offset_ += to_consume;
    return result;
  }

  // Extract remaining bytes
  std::vector<uint8_t> ConsumeRemainingBytes() {
    return ConsumeBytes(size_ - offset_);
  }

  // Check if more data is available
  bool HasData() const {
    return offset_ < size_;
  }

 private:
  const uint8_t* data_;
  size_t size_;
  size_t offset_;
};

// Create and populate iovec structures from fuzzed data
std::vector<std::vector<uint8_t>> CreateIOVecData(DataExtractor& extractor,
                                                  std::vector<struct iovec>& iovecs) {
  std::vector<std::vector<uint8_t>> buffers;
  
  // Determine number of iovec entries (1 to kMaxIOVecEntries)
  size_t num_iovecs = (extractor.ConsumeByte() % kMaxIOVecEntries) + 1;
  
  size_t total_size = 0;
  
  for (size_t i = 0; i < num_iovecs && extractor.HasData() && total_size < kMaxTotalSize; ++i) {
    // Determine size for this iovec entry (0 to 4096 bytes)
    size_t iovec_size = extractor.ConsumeByte() | (extractor.ConsumeByte() << 8);
    iovec_size %= 4096;
    
    // Limit total size to prevent excessive memory usage
    iovec_size = std::min(iovec_size, kMaxTotalSize - total_size);
    
    // Create buffer for this iovec entry
    std::vector<uint8_t> buffer = extractor.ConsumeBytes(iovec_size);
    
    // Only add non-empty buffers or occasionally add empty buffers for edge case testing
    if (!buffer.empty() || (extractor.ConsumeByte() & 0x1F) == 0) {
      total_size += buffer.size();
      buffers.push_back(std::move(buffer));
    }
  }
  
  // Populate iovec structures
  iovecs.resize(buffers.size());
  for (size_t i = 0; i < buffers.size(); ++i) {
    iovecs[i].iov_base = buffers[i].data();
    iovecs[i].iov_len = buffers[i].size();
  }
  
  return buffers;
}

// Test various operations with SnappyIOVecReader and SnappyIOVecWriter via public APIs
void TestIOVecCompression(const std::vector<struct iovec>& iovecs,
                         size_t total_size,
                         int compression_level) {
  // Test CompressFromIOVec (uses SnappyIOVecReader internally)
  std::string compressed_string;
  size_t compressed_size = snappy::CompressFromIOVec(
      iovecs.data(), iovecs.size(), &compressed_string,
      snappy::CompressionOptions{compression_level});
  
  (void)compressed_size;  // Variable only used in debug builds
  assert(compressed_size == compressed_string.size());
  assert(compressed_string.size() <= snappy::MaxCompressedLength(total_size));
  
  // Verify the compressed data is valid
  if (!compressed_string.empty()) {
    assert(snappy::IsValidCompressedBuffer(compressed_string.data(), 
                                          compressed_string.size()));
    
    // Test decompression to string
    std::string uncompressed;
    bool uncompress_succeeded = snappy::Uncompress(
        compressed_string.data(), compressed_string.size(), &uncompressed);
    
    if (uncompress_succeeded) {
      // Verify decompressed size matches original
      assert(uncompressed.size() == total_size);
      
      // Verify content matches by reconstructing original data
      std::string original_data;
      for (const auto& iov : iovecs) {
        original_data.append(static_cast<const char*>(iov.iov_base), iov.iov_len);
      }
      assert(uncompressed == original_data);
    }
  }
  
  // Test RawCompressFromIOVec (uses SnappyIOVecReader internally)
  if (total_size > 0) {
    size_t max_compressed_length = snappy::MaxCompressedLength(total_size);
    std::vector<char> raw_compressed(max_compressed_length);
    size_t raw_compressed_length = max_compressed_length;
    
    snappy::RawCompressFromIOVec(
        iovecs.data(), total_size, raw_compressed.data(), &raw_compressed_length,
        snappy::CompressionOptions{compression_level});
    
    assert(raw_compressed_length <= max_compressed_length);
    
    if (raw_compressed_length > 0) {
      assert(snappy::IsValidCompressedBuffer(raw_compressed.data(), 
                                            raw_compressed_length));
      
      // Test raw decompression to array
      std::vector<char> raw_uncompressed(total_size);
      bool raw_uncompress_succeeded = snappy::RawUncompress(
          raw_compressed.data(), raw_compressed_length, raw_uncompressed.data());
      
      if (raw_uncompress_succeeded) {
        // Verify content matches
        std::string original_data;
        for (const auto& iov : iovecs) {
          original_data.append(static_cast<const char*>(iov.iov_base), iov.iov_len);
        }
        std::string raw_result(raw_uncompressed.data(), total_size);
        assert(raw_result == original_data);
      }
    }
  }
}

// Test SnappyIOVecWriter by testing decompression to iovec arrays
void TestIOVecDecompression(DataExtractor& extractor, const std::string& compressed_data,
                           size_t expected_size) {
  if (compressed_data.empty() || expected_size == 0) return;
  
  // Create output iovec array with random buffer sizes (tests SnappyIOVecWriter)
  std::vector<std::vector<char>> output_buffers;
  std::vector<struct iovec> output_iovecs;
  
  size_t remaining = expected_size;
  size_t max_buffers = std::min(static_cast<size_t>(16), (expected_size / 10) + 1);
  
  // Create multiple output buffers of varying sizes
  for (size_t i = 0; i < max_buffers && remaining > 0; ++i) {
    size_t buffer_size;
    if (i == max_buffers - 1) {
      // Last buffer gets remaining bytes
      buffer_size = remaining;
    } else {
      // Random buffer size between 1 and remaining/2
      size_t max_size = std::max(static_cast<size_t>(1), remaining / 2);
      buffer_size = (extractor.ConsumeByte() % max_size) + 1;
      buffer_size = std::min(buffer_size, remaining);
    }
    
    output_buffers.emplace_back(buffer_size);
    remaining -= buffer_size;
  }
  
  // Set up iovec structures
  output_iovecs.resize(output_buffers.size());
  for (size_t i = 0; i < output_buffers.size(); ++i) {
    output_iovecs[i].iov_base = output_buffers[i].data();
    output_iovecs[i].iov_len = output_buffers[i].size();
  }
  
  // Test RawUncompressToIOVec (uses SnappyIOVecWriter internally)
  bool decompress_success = snappy::RawUncompressToIOVec(
      compressed_data.data(), compressed_data.size(),
      output_iovecs.data(), output_iovecs.size());
  
  if (decompress_success) {
    // Verify the decompressed data by reconstructing it
    std::string reconstructed;
    for (const auto& buffer : output_buffers) {
      reconstructed.append(buffer.data(), buffer.size());
    }
    assert(reconstructed.size() == expected_size);
  }
}

// Test edge cases and boundary conditions for both Reader and Writer
void TestEdgeCases(DataExtractor& extractor) {
  // Test empty iovec array (edge case for SnappyIOVecReader)
  std::vector<struct iovec> empty_iovecs;
  std::string empty_compressed;
  snappy::CompressFromIOVec(empty_iovecs.data(), 0, &empty_compressed);
  
  // Test single empty iovec entry
  std::vector<uint8_t> empty_buffer;
  std::vector<struct iovec> single_empty_iovec(1);
  single_empty_iovec[0].iov_base = empty_buffer.data();
  single_empty_iovec[0].iov_len = 0;
  
  std::string single_empty_compressed;
  snappy::CompressFromIOVec(single_empty_iovec.data(), 1, &single_empty_compressed);
  
  // Test with some zero-length entries mixed with data (tests Advance() logic in Reader)
  if (extractor.HasData()) {
    std::vector<std::vector<uint8_t>> mixed_buffers;
    std::vector<struct iovec> mixed_iovecs;
    
    // Add some empty entries and some with data
    for (size_t i = 0; i < 8 && extractor.HasData(); ++i) {
      if (i % 3 == 0 || !extractor.HasData()) {
        // Empty entry (tests SnappyIOVecReader::Advance() skipping empty iovecs)
        mixed_buffers.emplace_back();
      } else {
        // Non-empty entry
        size_t size = extractor.ConsumeByte() % 100;
        mixed_buffers.push_back(extractor.ConsumeBytes(size));
      }
    }
    
    // Set up iovecs
    mixed_iovecs.resize(mixed_buffers.size());
    size_t total_mixed_size = 0;
    for (size_t i = 0; i < mixed_buffers.size(); ++i) {
      mixed_iovecs[i].iov_base = mixed_buffers[i].data();
      mixed_iovecs[i].iov_len = mixed_buffers[i].size();
      total_mixed_size += mixed_buffers[i].size();
    }
    
    if (!mixed_iovecs.empty()) {
      TestIOVecCompression(mixed_iovecs, total_mixed_size, 1);
      
      // Test SnappyIOVecWriter with fragmented output buffers
      if (total_mixed_size > 0) {
        std::string test_data;
        for (const auto& iov : mixed_iovecs) {
          test_data.append(static_cast<const char*>(iov.iov_base), iov.iov_len);
        }
        
        std::string compressed;
        snappy::Compress(test_data.data(), test_data.size(), &compressed);
        
        if (!compressed.empty()) {
          TestIOVecDecompression(extractor, compressed, total_mixed_size);
        }
      }
    }
  }
  
  // Test SnappyIOVecWriter with very small output buffers (edge case testing)
  if (extractor.HasData()) {
    std::string small_test_data = "Hello, World!";
    std::string small_compressed;
    snappy::Compress(small_test_data.data(), small_test_data.size(), &small_compressed);
    
    if (!small_compressed.empty()) {
      // Create many very small output buffers (1-2 bytes each)
      std::vector<std::vector<char>> tiny_buffers;
      std::vector<struct iovec> tiny_iovecs;
      
      for (size_t i = 0; i < small_test_data.size(); ++i) {
        size_t buffer_size = (extractor.ConsumeByte() % 2) + 1;  // 1-2 bytes
        buffer_size = std::min(buffer_size, small_test_data.size() - i);
        if (buffer_size == 0) buffer_size = 1;
        
        tiny_buffers.emplace_back(buffer_size);
        tiny_iovecs.emplace_back();
        tiny_iovecs.back().iov_base = tiny_buffers.back().data();
        tiny_iovecs.back().iov_len = tiny_buffers.back().size();
        
        i += buffer_size - 1;  // Account for buffer size
      }
      
      // Test decompression to many tiny buffers (tests SnappyIOVecWriter's buffer management)
      bool tiny_decompress_success = snappy::RawUncompressToIOVec(
          small_compressed.data(), small_compressed.size(),
          tiny_iovecs.data(), tiny_iovecs.size());
      
      if (tiny_decompress_success) {
        std::string reconstructed;
        for (const auto& buffer : tiny_buffers) {
          reconstructed.append(buffer.data(), buffer.size());
        }
        assert(reconstructed.size() <= small_test_data.size());
      }
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;  // Need at least a few bytes to work with
  
  DataExtractor extractor(data, size);
  
  // Create iovec structures from fuzzed data
  std::vector<struct iovec> iovecs;
  std::vector<std::vector<uint8_t>> buffers = CreateIOVecData(extractor, iovecs);
  
  if (iovecs.empty()) return 0;
  
  // Calculate total size
  size_t total_size = 0;
  for (const auto& iov : iovecs) {
    total_size += iov.iov_len;
  }
  
  if (total_size > kMaxTotalSize) return 0;
  
  // Test with different compression levels
  std::string test_compressed_data;
  for (int level = snappy::CompressionOptions::MinCompressionLevel();
       level <= snappy::CompressionOptions::MaxCompressionLevel(); ++level) {
    TestIOVecCompression(iovecs, total_size, level);
    
    // Get compressed data for testing SnappyIOVecWriter
    if (test_compressed_data.empty() && total_size > 0) {
      snappy::CompressFromIOVec(iovecs.data(), iovecs.size(), &test_compressed_data,
                               snappy::CompressionOptions{level});
    }
  }
  
  // Test SnappyIOVecWriter with decompression if we have valid compressed data
  if (!test_compressed_data.empty() && total_size > 0) {
    TestIOVecDecompression(extractor, test_compressed_data, total_size);
  }
  
  // Test edge cases
  TestEdgeCases(extractor);
  
  return 0;
}