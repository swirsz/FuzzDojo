// Copyright 2019 Google Inc. All Rights Reserved.
// Enhanced fuzzer for Snappy targeting IOVec and Source/Sink APIs

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

#include "snappy.h"
#include "snappy-sinksource.h"

// FuzzedDataProvider for structured fuzzing
class FuzzedDataProvider {
 public:
  FuzzedDataProvider(const uint8_t* data, size_t size)
      : data_(data), size_(size), pos_(0) {}
  
  template<typename T>
  T ConsumeIntegral() {
    if (pos_ + sizeof(T) > size_) {
      return 0;
    }
    T value;
    memcpy(&value, data_ + pos_, sizeof(T));
    pos_ += sizeof(T);
    return value;
  }
  
  std::vector<uint8_t> ConsumeBytes(size_t num_bytes) {
    num_bytes = std::min(num_bytes, size_ - pos_);
    std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + num_bytes);
    pos_ += num_bytes;
    return result;
  }
  
  std::vector<uint8_t> ConsumeRemainingBytes() {
    return ConsumeBytes(size_ - pos_);
  }
  
  size_t remaining_bytes() const { return size_ - pos_; }
  
 private:
  const uint8_t* data_;
  size_t size_;
  size_t pos_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 10) return 0;
  
  FuzzedDataProvider provider(data, size);
  
  // Use first byte to decide operation mode
  uint8_t mode = provider.ConsumeIntegral<uint8_t>() % 8;
  
  // Get compression options
  uint8_t level_byte = provider.ConsumeIntegral<uint8_t>();
  int level = (level_byte % 2) + 1; // Level 1 or 2
  snappy::CompressionOptions options;
  options.level = level;
  
  // Get remaining data for actual fuzzing
  auto fuzz_data = provider.ConsumeRemainingBytes();
  if (fuzz_data.empty()) return 0;
  
  std::string input(fuzz_data.begin(), fuzz_data.end());
  
  switch (mode) {
    case 0: {
      // Standard compress/decompress with different compression levels
      std::string compressed;
      snappy::Compress(input.data(), input.size(), &compressed, options);
      
      std::string uncompressed;
      snappy::Uncompress(compressed.data(), compressed.size(), &uncompressed);
      break;
    }
    
    case 1: {
      // IOVec compression - create multiple iovecs
      size_t num_iov = std::min<size_t>(input.size() / 10 + 1, 20);
      std::vector<struct iovec> iov(num_iov);
      
      size_t offset = 0;
      for (size_t i = 0; i < num_iov && offset < input.size(); ++i) {
        size_t chunk_size = std::min<size_t>(
            (input.size() - offset) / (num_iov - i),
            input.size() - offset
        );
        iov[i].iov_base = const_cast<char*>(input.data() + offset);
        iov[i].iov_len = chunk_size;
        offset += chunk_size;
      }
      
      std::string compressed;
      snappy::CompressFromIOVec(iov.data(), num_iov, &compressed, options);
      
      // Decompress back
      std::string uncompressed;
      snappy::Uncompress(compressed.data(), compressed.size(), &uncompressed);
      break;
    }
    
    case 2: {
      // IOVec decompression - compress first, then decompress to IOVec
      std::string compressed;
      snappy::Compress(input.data(), input.size(), &compressed, options);
      
      // Create iovec for output
      size_t num_iov = std::min<size_t>(input.size() / 10 + 1, 20);
      std::vector<char> output_buffer(input.size() + 100);
      std::vector<struct iovec> iov(num_iov);
      
      size_t offset = 0;
      for (size_t i = 0; i < num_iov && offset < output_buffer.size(); ++i) {
        size_t chunk_size = std::min<size_t>(
            (output_buffer.size() - offset) / (num_iov - i),
            output_buffer.size() - offset
        );
        iov[i].iov_base = output_buffer.data() + offset;
        iov[i].iov_len = chunk_size;
        offset += chunk_size;
      }
      
      snappy::RawUncompressToIOVec(compressed.data(), compressed.size(),
                                    iov.data(), num_iov);
      break;
    }
    
    case 3: {
      // Source/Sink API testing
      snappy::ByteArraySource source(input.data(), input.size());
      std::string compressed;
      compressed.resize(snappy::MaxCompressedLength(input.size()));
      snappy::UncheckedByteArraySink sink(const_cast<char*>(compressed.data()));
      
      snappy::Compress(&source, &sink, options);
      
      // Decompress using Source/Sink
      snappy::ByteArraySource comp_source(compressed.data(), compressed.size());
      std::string uncompressed;
      uncompressed.resize(input.size());
      snappy::UncheckedByteArraySink uncomp_sink(const_cast<char*>(uncompressed.data()));
      snappy::Uncompress(&comp_source, &uncomp_sink);
      break;
    }
    
    case 4: {
      // RawCompress with IOVec source
      std::vector<char> output(snappy::MaxCompressedLength(input.size()));
      
      // Create fragmented input
      size_t num_iov = std::min<size_t>(input.size() / 5 + 1, 15);
      std::vector<struct iovec> iov(num_iov);
      size_t offset = 0;
      for (size_t i = 0; i < num_iov && offset < input.size(); ++i) {
        size_t chunk_size = std::min<size_t>(
            (input.size() - offset) / (num_iov - i),
            input.size() - offset
        );
        iov[i].iov_base = const_cast<char*>(input.data() + offset);
        iov[i].iov_len = chunk_size;
        offset += chunk_size;
      }
      
      size_t compressed_length;
      snappy::RawCompressFromIOVec(iov.data(), input.size(),
                                    output.data(), &compressed_length, options);
      
      // Validate
      snappy::IsValidCompressedBuffer(output.data(), compressed_length);
      break;
    }
    
    case 5: {
      // Direct decompression fuzzing - use input as potentially compressed data
      std::string uncompressed;
      size_t ulength;
      
      // Try to get uncompressed length
      if (snappy::GetUncompressedLength(input.data(), input.size(), &ulength)) {
        if (ulength > 0 && ulength < 128 * 1024) { // Reasonable limit: 128KB
          snappy::Uncompress(input.data(), input.size(), &uncompressed);
        }
      }
      
      // Also test validation
      snappy::IsValidCompressedBuffer(input.data(), input.size());
      break;
    }
    
    case 6: {
      // UncompressAsMuchAsPossible - tests scattered writer
      std::string compressed;
      snappy::Compress(input.data(), input.size(), &compressed, options);
      
      snappy::ByteArraySource source(compressed.data(), compressed.size());
      
      // Custom sink that fragments output
      class FragmentedSink : public snappy::Sink {
       public:
        void Append(const char* bytes, size_t n) override {
          data_.append(bytes, n);
        }
        
        char* GetAppendBuffer(size_t length, char* /*scratch*/) override {
          // Return small buffers to exercise edge cases
          size_t alloc = std::min(length, size_t(64));
          temp_.resize(alloc);
          return temp_.data();
        }
        
        void AppendAndTakeOwnership(char* bytes, size_t n,
                                   void (*deleter)(void*, const char*, size_t),
                                   void* deleter_arg) override {
          data_.append(bytes, n);
          if (deleter) deleter(deleter_arg, bytes, n);
        }
        
        std::string data_;
       private:
        std::vector<char> temp_;
      };
      
      FragmentedSink sink;
      snappy::Uncompress(&source, &sink);
      break;
    }
    
    case 7: {
      // Test with small IOVec fragments (edge cases)
      if (input.size() < 5) break;
      
      std::vector<struct iovec> iov;
      iov.reserve(50); // Limit maximum IOVec entries
      size_t pos = 0;
      
      // Create many small fragments, including zero-length ones
      while (pos < input.size() && iov.size() < 50) {
        struct iovec v;
        size_t chunk = std::min<size_t>(input[pos % input.size()] % 10 + 1, input.size() - pos);
        v.iov_base = const_cast<char*>(input.data() + pos);
        v.iov_len = chunk;
        iov.push_back(v);
        pos += chunk;
        
        // Occasionally add zero-length iovec
        if (pos < input.size() && (input[pos % input.size()] & 1) && iov.size() < 50) {
          struct iovec zero_v;
          zero_v.iov_base = const_cast<char*>(input.data() + pos);
          zero_v.iov_len = 0;
          iov.push_back(zero_v);
        }
      }
      
      if (!iov.empty()) {
        std::string compressed;
        snappy::CompressFromIOVec(iov.data(), iov.size(), &compressed, options);
      }
      break;
    }
  }
  
  return 0;
}