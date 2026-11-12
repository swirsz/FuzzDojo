/*
 * Copyright (c) 2025 The libvpx project authors. All Rights Reserved.
 *
 * VP9 Multi-threaded Tile Decoding Fuzzer
 * Targets race conditions and synchronization bugs in parallel decode
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <vector>
#include <algorithm>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_image.h"

namespace {

// Configuration strategies to maximize thread contention
enum ThreadingStrategy {
  THREADS_1 = 0,      // Baseline single-threaded
  THREADS_2,          // 2 threads
  THREADS_4,          // 4 threads  
  THREADS_8,          // 8 threads
  THREADS_16,         // 16 threads (max, high contention)
  THREADS_DYNAMIC,    // Change thread count per frame
  THREADS_MAX
};

enum FrameParallelMode {
  FRAME_PARALLEL_OFF = 0,
  FRAME_PARALLEL_ON,
  FRAME_PARALLEL_TOGGLE,  // Toggle between frames
  FRAME_PARALLEL_MAX
};

class VP9ThreadingFuzzer {
 public:
  VP9ThreadingFuzzer() : frame_count_(0) {}
  
  ~VP9ThreadingFuzzer() {
    // Clean up all decoder instances
    for (auto* ctx : decoders_) {
      if (ctx) {
        vpx_codec_destroy(ctx);
        delete ctx;
      }
    }
    decoders_.clear();
  }

  // Main fuzzing function
  void FuzzDecode(const uint8_t *data, size_t size) {
    if (size < 5) return;

    // Extract configuration from input
    ThreadingStrategy thread_strategy = 
        static_cast<ThreadingStrategy>(data[0] % THREADS_MAX);
    FrameParallelMode frame_parallel = 
        static_cast<FrameParallelMode>(data[1] % FRAME_PARALLEL_MAX);
    bool use_postproc = (data[2] & 0x01);
    bool use_multiple_decoders = (data[2] & 0x02);
    
    // Actual VP9 data starts at offset 3
    const uint8_t *vp9_data = data + 3;
    size_t vp9_size = size - 3;

    if (use_multiple_decoders) {
      // Test with multiple decoder instances (simulates multi-tab browser)
      FuzzMultipleDecoders(vp9_data, vp9_size, thread_strategy, frame_parallel);
    } else {
      // Single decoder with various threading configs
      FuzzSingleDecoder(vp9_data, vp9_size, thread_strategy, 
                       frame_parallel, use_postproc);
    }

    frame_count_++;
  }

 private:
  void FuzzSingleDecoder(const uint8_t *data, size_t size,
                         ThreadingStrategy thread_strategy,
                         FrameParallelMode frame_parallel,
                         bool use_postproc) {
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    
    // Configure decoder with threading
    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = GetThreadCount(thread_strategy);
    
    // Enable frame parallel mode if requested
    int flags = 0;
    if (ShouldUseFrameParallel(frame_parallel)) {
      flags |= VPX_CODEC_USE_FRAME_THREADING;
    }

    vpx_codec_err_t res = vpx_codec_dec_init(
        &codec, vpx_codec_vp9_dx(), &cfg, flags);
    
    if (res != VPX_CODEC_OK) {
      return;
    }

    // Optionally enable post-processing (adds more parallel work)
    if (use_postproc) {
      vp8_postproc_cfg_t pp_cfg;
      pp_cfg.post_proc_flag = VP8_DEMACROBLOCK | VP8_DEBLOCK;
      pp_cfg.deblocking_level = 4;
      vpx_codec_control(&codec, VP8_SET_POSTPROC, &pp_cfg);
    }

    // Decode the frame
    DecodeWithThreading(&codec, data, size);

    vpx_codec_destroy(&codec);
  }

  void FuzzMultipleDecoders(const uint8_t *data, size_t size,
                           ThreadingStrategy thread_strategy,
                           FrameParallelMode frame_parallel) {
    // Create 2-4 decoder instances
    int num_decoders = 2 + (data[0] % 3);
    std::vector<vpx_codec_ctx_t*> local_decoders;

    for (int i = 0; i < num_decoders; i++) {
      vpx_codec_ctx_t* codec = new vpx_codec_ctx_t;
      memset(codec, 0, sizeof(*codec));

      vpx_codec_dec_cfg_t cfg = {0};
      // Vary thread counts across decoders for more race conditions
      cfg.threads = 1 + (i * 2);
      
      int flags = 0;
      if (ShouldUseFrameParallel(frame_parallel)) {
        flags |= VPX_CODEC_USE_FRAME_THREADING;
      }

      vpx_codec_err_t res = vpx_codec_dec_init(
          codec, vpx_codec_vp9_dx(), &cfg, flags);
      
      if (res == VPX_CODEC_OK) {
        local_decoders.push_back(codec);
      } else {
        delete codec;
      }
    }

    // Decode same data with all decoders (simulates resource contention)
    for (auto* codec : local_decoders) {
      DecodeWithThreading(codec, data, size);
    }

    // Cleanup
    for (auto* codec : local_decoders) {
      vpx_codec_destroy(codec);
      delete codec;
    }
  }

  void DecodeWithThreading(vpx_codec_ctx_t *codec, 
                          const uint8_t *data, size_t size) {
    if (size == 0 || !codec) return;

    // Decode frame - threading happens internally
    vpx_codec_err_t err = vpx_codec_decode(codec, data, size, nullptr, 0);

    // Retrieve frames - this also exercises thread synchronization
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;
    
    int frame_idx = 0;
    while ((img = vpx_codec_get_frame(codec, &iter)) != nullptr) {
      // Access frame data to ensure decode completed
      TouchFrameData(img);
      frame_idx++;
      
      // Test rapid iteration (stresses buffer management)
      if (frame_idx > 10) break;
    }

    // Test control operations during/after decode
    TestControlOperations(codec);
  }

  void TouchFrameData(vpx_image_t *img) {
    if (!img || img->d_w == 0 || img->d_h == 0) return;

    // Touch all planes to ensure they're valid and accessible
    for (int plane = 0; plane < 3; plane++) {
      if (img->planes[plane] && img->stride[plane] > 0) {
        // Touch corners and center of each plane
        int w = (plane == 0) ? img->d_w : (img->d_w + 1) / 2;
        int h = (plane == 0) ? img->d_h : (img->d_h + 1) / 2;
        
        if (w > 0 && h > 0) {
          volatile uint8_t corner = img->planes[plane][0];
          if (h > 1 && img->stride[plane] * (h - 1) < img->stride[plane] * h) {
            volatile uint8_t bottom = 
                img->planes[plane][img->stride[plane] * (h - 1)];
            (void)bottom;
          }
          (void)corner;
        }
      }
    }
  }

  void TestControlOperations(vpx_codec_ctx_t *codec) {
    // Test various control operations that interact with threading
    
    // Get frame corruption status (exercises decoder state)
    int corrupted = 0;
    vpx_codec_control(codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);
    
    // Get display frame size (exercises frame info access)
    int width = 0, height = 0;
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &width);
    (void)height;  // Suppress unused warning
    
    // Get last decoded frame size
    int frame_width = 0;
    vpx_codec_control(codec, VP9D_GET_FRAME_SIZE, &frame_width);
  }

  int GetThreadCount(ThreadingStrategy strategy) {
    switch (strategy) {
      case THREADS_1: return 1;
      case THREADS_2: return 2;
      case THREADS_4: return 4;
      case THREADS_8: return 8;
      case THREADS_16: return 16;
      case THREADS_DYNAMIC:
        // Change thread count based on frame number
        return 1 + (frame_count_ % 8);
      default: return 4;
    }
  }

  bool ShouldUseFrameParallel(FrameParallelMode mode) {
    switch (mode) {
      case FRAME_PARALLEL_OFF: return false;
      case FRAME_PARALLEL_ON: return true;
      case FRAME_PARALLEL_TOGGLE:
        // Toggle every 3 frames to stress init/deinit
        return (frame_count_ / 3) % 2 == 0;
      default: return false;
    }
  }

  std::vector<vpx_codec_ctx_t*> decoders_;
  int frame_count_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Need minimum bytes for config + VP9 data
  if (size < 10 || size > 8 * 1024 * 1024) {  // Max 8MB
    return 0;
  }

  // Use thread-local storage to maintain state across inputs
  // This helps find bugs related to state accumulation
  static thread_local VP9ThreadingFuzzer fuzzer;
  
  fuzzer.FuzzDecode(data, size);

  return 0;
}


