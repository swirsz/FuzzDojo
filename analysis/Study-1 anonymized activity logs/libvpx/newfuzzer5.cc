/*
 * Copyright (c) 2025 The libvpx project authors. All Rights Reserved.
 *
 * VP9 Decoder Error Resilience Fuzzer
 * Targets error handling paths by corrupting valid VP9 bitstreams
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <algorithm>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_image.h"

namespace {

// Corruption strategies to trigger error paths
enum CorruptionType {
  CORRUPT_NONE = 0,
  CORRUPT_FRAME_HEADER,      // Corrupt frame header bytes
  CORRUPT_TILE_BOUNDARIES,   // Corrupt tile size/offset data
  CORRUPT_PARTITION_TREE,    // Corrupt partition structure
  CORRUPT_FRAME_REFERENCES,  // Corrupt reference frame indices
  CORRUPT_TRUNCATE,          // Truncate frame mid-decode
  CORRUPT_DIMENSIONS,        // Corrupt frame dimensions
  CORRUPT_SUPERBLOCK,        // Corrupt superblock data
  CORRUPT_MV_DATA,           // Corrupt motion vector data
  CORRUPT_COEFFICIENT,       // Corrupt coefficient data
  CORRUPT_MAX
};

class VP9ErrorFuzzer {
 public:
  VP9ErrorFuzzer() {
    memset(&codec_, 0, sizeof(codec_));
    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = 1;  // Single thread for determinism
    
    vpx_codec_err_t res = vpx_codec_dec_init(
        &codec_, vpx_codec_vp9_dx(), &cfg, 0);
    
    initialized_ = (res == VPX_CODEC_OK);
  }

  ~VP9ErrorFuzzer() {
    if (initialized_) {
      vpx_codec_destroy(&codec_);
    }
  }

  bool IsInitialized() const { return initialized_; }

  // Main fuzzing function
  void FuzzDecode(const uint8_t *data, size_t size) {
    if (!initialized_ || size < 10) return;

    // Use first byte to determine corruption strategy
    CorruptionType corruption = 
        static_cast<CorruptionType>(data[0] % CORRUPT_MAX);
    
    // Use second byte for corruption intensity (0-255)
    uint8_t intensity = data[1];
    
    // Actual VP9 data starts at offset 2
    const uint8_t *vp9_data = data + 2;
    size_t vp9_size = size - 2;

    // Create mutable copy for corruption
    std::unique_ptr<uint8_t[]> corrupted_data(new uint8_t[vp9_size]);
    memcpy(corrupted_data.get(), vp9_data, vp9_size);

    // Apply intelligent corruption based on strategy
    ApplyCorruption(corrupted_data.get(), vp9_size, corruption, intensity);

    // Attempt to decode the corrupted stream
    DecodeFrame(corrupted_data.get(), vp9_size);
  }

 private:
  void ApplyCorruption(uint8_t *data, size_t size, 
                       CorruptionType type, uint8_t intensity) {
    if (size < 10) return;

    switch (type) {
      case CORRUPT_NONE:
        // No corruption - test valid streams too
        break;

      case CORRUPT_FRAME_HEADER:
        // Corrupt frame header (first 8-20 bytes typically)
        if (size >= 10) {
          size_t header_size = std::min(size, size_t(20));
          for (size_t i = 0; i < header_size && i < intensity / 16; i++) {
            data[i] ^= (intensity >> (i % 8));
          }
        }
        break;

      case CORRUPT_TILE_BOUNDARIES:
        // Corrupt tile size markers (typically after frame header)
        if (size >= 20) {
          size_t pos = 10 + (intensity % 10);
          if (pos < size - 4) {
            // Corrupt 4 bytes that might be tile sizes
            data[pos] ^= 0xFF;
            data[pos + 1] ^= (intensity >> 1);
            data[pos + 2] = 0xFF;  // Invalid size
          }
        }
        break;

      case CORRUPT_PARTITION_TREE:
        // Corrupt middle section (partition tree data)
        if (size >= 30) {
          size_t start = size / 4;
          size_t end = size / 2;
          for (size_t i = start; i < end && i < start + (intensity / 8); i++) {
            data[i] = ~data[i];
          }
        }
        break;

      case CORRUPT_FRAME_REFERENCES:
        // Corrupt reference frame indices (early in frame header)
        if (size >= 15) {
          // Reference indices typically in bytes 10-15
          for (size_t i = 10; i < 15 && i < size; i++) {
            data[i] |= 0xE0;  // Set high bits to create invalid refs
          }
        }
        break;

      case CORRUPT_TRUNCATE:
        // Simulate truncated frame by "hiding" data
        if (size > 20) {
          size_t new_size = 10 + (intensity * size / 512);
          if (new_size < size) {
            memset(data + new_size, 0, size - new_size);
          }
        }
        break;

      case CORRUPT_DIMENSIONS:
        // Corrupt frame dimension fields
        if (size >= 12) {
          // Width/height typically in bytes 6-12
          data[6] = 0xFF;
          data[7] = 0xFF;
          data[8] ^= intensity;
          data[9] = (intensity > 128) ? 0xFF : 0x00;
        }
        break;

      case CORRUPT_SUPERBLOCK:
        // Corrupt superblock coefficient data (later in stream)
        if (size >= 50) {
          size_t sb_start = size / 3;
          size_t sb_end = (2 * size) / 3;
          for (size_t i = sb_start; 
               i < sb_end && i < sb_start + (intensity / 4); i++) {
            data[i] ^= (intensity ^ i);
          }
        }
        break;

      case CORRUPT_MV_DATA:
        // Corrupt motion vector data
        if (size >= 40) {
          for (size_t i = 20; i < 40 && i < size; i++) {
            data[i] = (data[i] << 4) | (data[i] >> 4);  // Swap nibbles
          }
        }
        break;

      case CORRUPT_COEFFICIENT:
        // Corrupt coefficient data (end of stream)
        if (size >= 30) {
          size_t coeff_start = (2 * size) / 3;
          for (size_t i = coeff_start; 
               i < size && i < coeff_start + (intensity / 2); i++) {
            data[i] = 0xFF;  // Max value to trigger overflow checks
          }
        }
        break;

      default:
        break;
    }
  }

  void DecodeFrame(const uint8_t *data, size_t size) {
    if (size == 0) return;

    // Attempt to decode - errors are expected and handled internally
    vpx_codec_err_t err = vpx_codec_decode(
        &codec_, data, size, nullptr, 0);

    // Iterate through available frames (even on error, partial decode may occur)
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;
    
    while ((img = vpx_codec_get_frame(&codec_, &iter)) != nullptr) {
      // Successfully decoded frame - touch the data to ensure it's valid
      if (img->d_w > 0 && img->d_h > 0 && img->planes[0]) {
        volatile uint8_t touch = img->planes[0][0];
        (void)touch;
      }
    }

    // Check for decoder errors (expected in this fuzzer)
    if (err != VPX_CODEC_OK) {
      const char *error_detail = vpx_codec_error_detail(&codec_);
      // Error detail retrieval exercises error path code
      (void)error_detail;
    }
  }

  vpx_codec_ctx_t codec_;
  bool initialized_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Need at least 10 bytes: 2 for control + 8 minimum VP9 frame
  if (size < 10 || size > 4 * 1024 * 1024) {  // Max 4MB
    return 0;
  }

  static VP9ErrorFuzzer fuzzer;
  
  if (!fuzzer.IsInitialized()) {
    return 0;
  }

  fuzzer.FuzzDecode(data, size);

  return 0;
}


