/*
 * Copyright (c) 2025 The libvpx project authors. All Rights Reserved.
 *
 * VP8/VP9 Hybrid Ultra-Coverage Fuzzer
 * Goal: Maximum LOC by testing BOTH VP8 and VP9 plus all shared code
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <vector>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8.h"

namespace {

// Codec selection
enum CodecType {
  CODEC_VP8 = 0,
  CODEC_VP9,
  CODEC_AUTO_DETECT,
  CODEC_BOTH_SEQUENCE,  // Decode with both codecs
  CODEC_MAX
};

// Image format conversions
enum ImageFormatOp {
  IMG_NO_CONVERT = 0,
  IMG_CONVERT_YV12,
  IMG_CONVERT_I420,
  IMG_CONVERT_I422,
  IMG_CONVERT_I444,
  IMG_FLIP_VERTICAL,
  IMG_FLIP_HORIZONTAL,
  IMG_MAX
};

// Boundary conditions
enum BoundaryTest {
  BOUNDARY_NONE = 0,
  BOUNDARY_TINY_FRAME,      // Minimum resolution
  BOUNDARY_HUGE_FRAME,      // Maximum resolution  
  BOUNDARY_ODD_DIMENSIONS,  // Non-standard sizes
  BOUNDARY_TRUNCATE_EARLY,  // Cut off early
  BOUNDARY_TRUNCATE_LATE,   // Cut off near end
  BOUNDARY_SPLIT_FRAMES,    // Split into fragments
  BOUNDARY_MAX
};

// Control operation combinations
enum ControlCombo {
  CTRL_COMBO_NONE = 0,
  CTRL_COMBO_VP8_ALL,
  CTRL_COMBO_VP9_ALL,
  CTRL_COMBO_MIXED,
  CTRL_COMBO_ERROR_CHECKS,
  CTRL_COMBO_POSTPROC_ALL,
  CTRL_COMBO_BUFFER_QUERIES,
  CTRL_COMBO_MAX
};

class VPXHybridMaxCoverage {
 public:
  VPXHybridMaxCoverage() : iteration_(0) {}
  
  ~VPXHybridMaxCoverage() {
    CleanupDecoders();
  }

  void FuzzDecode(const uint8_t *data, size_t size) {
    if (size < 12) return;

    // Parse configuration
    CodecType codec = static_cast<CodecType>(data[0] % CODEC_MAX);
    ImageFormatOp img_op = static_cast<ImageFormatOp>(data[1] % IMG_MAX);
    BoundaryTest boundary = static_cast<BoundaryTest>(data[2] % BOUNDARY_MAX);
    ControlCombo ctrl = static_cast<ControlCombo>(data[3] % CTRL_COMBO_MAX);
    uint8_t thread_count = (data[4] % 16) + 1;  // 1-16 threads
    uint8_t postproc_level = data[5] % 16;
    bool use_frame_parallel = (data[6] & 0x01);
    bool use_error_concealment = (data[6] & 0x02);
    bool peek_mode = (data[6] & 0x04);
    bool reverse_iteration = (data[6] & 0x08);
    
    // Data starts at offset 7
    const uint8_t *codec_data = data + 7;
    size_t codec_size = size - 7;

    // Apply boundary test modifications
    std::vector<uint8_t> modified_data;
    const uint8_t *final_data = codec_data;
    size_t final_size = codec_size;
    
    if (ApplyBoundaryTest(codec_data, codec_size, boundary, modified_data)) {
      final_data = modified_data.data();
      final_size = modified_data.size();
    }

    // Decode based on codec type
    switch (codec) {
      case CODEC_VP8:
        DecodeVP8(final_data, final_size, thread_count, postproc_level, 
                  peek_mode, ctrl);
        break;
      case CODEC_VP9:
        DecodeVP9(final_data, final_size, thread_count, use_frame_parallel,
                  peek_mode, ctrl);
        break;
      case CODEC_AUTO_DETECT:
        DecodeAutoDetect(final_data, final_size, thread_count);
        break;
      case CODEC_BOTH_SEQUENCE:
        DecodeBothCodecs(final_data, final_size, thread_count);
        break;
      default:
        DecodeVP9(final_data, final_size, thread_count, use_frame_parallel,
                  peek_mode, ctrl);
        break;
    }

    iteration_++;
  }

 private:
  void DecodeVP8(const uint8_t *data, size_t size, int threads,
                 int postproc_level, bool peek, ControlCombo ctrl) {
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = threads;

    if (vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), &cfg, 0) != VPX_CODEC_OK) {
      return;
    }

    // Configure VP8 post-processing
    if (postproc_level > 0) {
      vp8_postproc_cfg_t pp;
      pp.post_proc_flag = VP8_DEBLOCK | VP8_DEMACROBLOCK;
      pp.deblocking_level = postproc_level;
      vpx_codec_control(&codec, VP8_SET_POSTPROC, &pp);
    }

    // Decode
    vpx_codec_decode(&codec, data, size, nullptr, 0);

    // Get frames
    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t *img = vpx_codec_get_frame(&codec, &iter)) {
      ProcessImage(img);
      if (peek) break;  // Only peek at first frame
    }

    // Exercise VP8-specific controls
    ExerciseVP8Controls(&codec, ctrl);

    vpx_codec_destroy(&codec);
  }

  void DecodeVP9(const uint8_t *data, size_t size, int threads,
                 bool frame_parallel, bool peek, ControlCombo ctrl) {
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = threads;

    int flags = frame_parallel ? VPX_CODEC_USE_FRAME_THREADING : 0;

    if (vpx_codec_dec_init(&codec, vpx_codec_vp9_dx(), &cfg, flags) != VPX_CODEC_OK) {
      return;
    }

    // Decode
    vpx_codec_decode(&codec, data, size, nullptr, 0);

    // Get frames
    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t *img = vpx_codec_get_frame(&codec, &iter)) {
      ProcessImage(img);
      if (peek) break;
    }

    // Exercise VP9-specific controls
    ExerciseVP9Controls(&codec, ctrl);

    vpx_codec_destroy(&codec);
  }

  void DecodeAutoDetect(const uint8_t *data, size_t size, int threads) {
    // Try VP9 first (more common now)
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = threads;

    vpx_codec_iface_t *iface = nullptr;
    
    // Detect codec by trying to peek at stream
    if (size >= 4) {
      // VP9 frame marker: 0x82 0x49 0x83 0x42
      if (data[0] == 0x82 && data[1] == 0x49 && 
          data[2] == 0x83 && data[3] == 0x42) {
        iface = vpx_codec_vp9_dx();
      } else {
        // Try VP8
        iface = vpx_codec_vp8_dx();
      }
    } else {
      iface = vpx_codec_vp9_dx();
    }

    if (vpx_codec_dec_init(&codec, iface, &cfg, 0) == VPX_CODEC_OK) {
      vpx_codec_decode(&codec, data, size, nullptr, 0);
      
      vpx_codec_iter_t iter = nullptr;
      while (vpx_image_t *img = vpx_codec_get_frame(&codec, &iter)) {
        ProcessImage(img);
      }
      
      vpx_codec_destroy(&codec);
    }
  }

  void DecodeBothCodecs(const uint8_t *data, size_t size, int threads) {
    // Decode same data with both VP8 and VP9 (exercises both code paths)
    
    // VP8
    vpx_codec_ctx_t vp8_codec;
    memset(&vp8_codec, 0, sizeof(vp8_codec));
    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = threads / 2;  // Split threads
    
    if (vpx_codec_dec_init(&vp8_codec, vpx_codec_vp8_dx(), &cfg, 0) == VPX_CODEC_OK) {
      vpx_codec_decode(&vp8_codec, data, size, nullptr, 0);
      vpx_codec_iter_t iter = nullptr;
      while (vpx_image_t *img = vpx_codec_get_frame(&vp8_codec, &iter)) {
        ProcessImage(img);
      }
      vpx_codec_destroy(&vp8_codec);
    }

    // VP9
    vpx_codec_ctx_t vp9_codec;
    memset(&vp9_codec, 0, sizeof(vp9_codec));
    cfg.threads = (threads + 1) / 2;
    
    if (vpx_codec_dec_init(&vp9_codec, vpx_codec_vp9_dx(), &cfg, 0) == VPX_CODEC_OK) {
      vpx_codec_decode(&vp9_codec, data, size, nullptr, 0);
      vpx_codec_iter_t iter = nullptr;
      while (vpx_image_t *img = vpx_codec_get_frame(&vp9_codec, &iter)) {
        ProcessImage(img);
      }
      vpx_codec_destroy(&vp9_codec);
    }
  }

  bool ApplyBoundaryTest(const uint8_t *data, size_t size, 
                         BoundaryTest test,
                         std::vector<uint8_t> &output) {
    switch (test) {
      case BOUNDARY_NONE:
        return false;

      case BOUNDARY_TINY_FRAME:
        // Inject tiny frame dimensions (48x48 minimum)
        if (size >= 20) {
          output.assign(data, data + size);
          // Modify frame size bytes (approximate locations)
          output[10] = 0x30;  // Width low
          output[11] = 0x00;  // Width high
          output[12] = 0x30;  // Height low
          output[13] = 0x00;  // Height high
          return true;
        }
        return false;

      case BOUNDARY_HUGE_FRAME:
        // Inject large frame dimensions
        if (size >= 20) {
          output.assign(data, data + size);
          output[10] = 0xFF;
          output[11] = 0x1F;  // 8191
          output[12] = 0xFF;
          output[13] = 0x1F;
          return true;
        }
        return false;

      case BOUNDARY_ODD_DIMENSIONS:
        // Odd non-standard dimensions
        if (size >= 20) {
          output.assign(data, data + size);
          output[10] = 0x9D;  // 413
          output[11] = 0x01;
          output[12] = 0xE5;  // 485
          output[13] = 0x01;
          return true;
        }
        return false;

      case BOUNDARY_TRUNCATE_EARLY:
        // Truncate to 25% of size
        if (size > 20) {
          output.assign(data, data + (size / 4));
          return true;
        }
        return false;

      case BOUNDARY_TRUNCATE_LATE:
        // Truncate to 90% of size
        if (size > 20) {
          output.assign(data, data + (size * 9 / 10));
          return true;
        }
        return false;

      case BOUNDARY_SPLIT_FRAMES:
        // Take middle portion
        if (size > 40) {
          size_t start = size / 4;
          size_t end = (3 * size) / 4;
          output.assign(data + start, data + end);
          return true;
        }
        return false;

      default:
        return false;
    }
  }

  void ProcessImage(vpx_image_t *img) {
    if (!img) return;

    // Access all planes
    for (int plane = 0; plane < 3; plane++) {
      if (img->planes[plane]) {
        int w = (plane == 0) ? img->d_w : ((img->d_w + img->x_chroma_shift) >> img->x_chroma_shift);
        int h = (plane == 0) ? img->d_h : ((img->d_h + img->y_chroma_shift) >> img->y_chroma_shift);
        
        if (w > 0 && h > 0 && img->stride[plane] > 0) {
          // Touch corners
          volatile uint8_t v1 = img->planes[plane][0];
          if (w > 1 && h > 1) {
            volatile uint8_t v2 = img->planes[plane][w - 1];
            volatile uint8_t v3 = img->planes[plane][img->stride[plane] * (h - 1)];
            (void)v2; (void)v3;
          }
          (void)v1;
        }
      }
    }

    // Check format flags
    if (img->fmt & VPX_IMG_FMT_PLANAR) {
      // Planar format
    }
    if (img->fmt & VPX_IMG_FMT_HAS_ALPHA) {
      if (img->planes[VPX_PLANE_ALPHA]) {
        volatile uint8_t a = img->planes[VPX_PLANE_ALPHA][0];
        (void)a;
      }
    }
    if (img->fmt & VPX_IMG_FMT_HIGHBITDEPTH) {
      // High bit depth
    }

    // Access image properties
    volatile unsigned int fmt = img->fmt;
    volatile unsigned int cs = img->cs;
    volatile unsigned int range = img->range;
    (void)fmt; (void)cs; (void)range;
  }

  void ExerciseVP8Controls(vpx_codec_ctx_t *codec, ControlCombo combo) {
    if (!codec) return;

    // VP8-specific controls
    int corrupted = 0;
    vpx_codec_control(codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);

    // Post-processing variations
    if (combo == CTRL_COMBO_VP8_ALL || combo == CTRL_COMBO_POSTPROC_ALL) {
      for (int level = 0; level < 4; level++) {
        vp8_postproc_cfg_t pp;
        pp.post_proc_flag = (level & 1) ? VP8_DEBLOCK : 0;
        pp.post_proc_flag |= (level & 2) ? VP8_DEMACROBLOCK : 0;
        pp.deblocking_level = level * 4;
        vpx_codec_control(codec, VP8_SET_POSTPROC, &pp);
      }
    }

    // Reference frame operations are tricky - skip copy operations
    // that require pre-allocated buffers. Just query corruption status
    // which is safer and still exercises decoder state.

    // Error checking
    if (vpx_codec_error(codec)) {
      const char *detail = vpx_codec_error_detail(codec);
      (void)detail;
    }
  }

  void ExerciseVP9Controls(vpx_codec_ctx_t *codec, ControlCombo combo) {
    if (!codec) return;

    // Corruption check
    int corrupted = 0;
    vpx_codec_control(codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);

    // Display size
    int width = 0, height = 0;
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &width);
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &height);

    // Frame size
    int frame_size = 0;
    vpx_codec_control(codec, VP9D_GET_FRAME_SIZE, &frame_size);

    // Bit depth
    unsigned int bit_depth = 0;
    vpx_codec_control(codec, VP9D_GET_BIT_DEPTH, &bit_depth);

    // Post-processing for VP9
    if (combo == CTRL_COMBO_VP9_ALL || combo == CTRL_COMBO_POSTPROC_ALL) {
      vp8_postproc_cfg_t pp;
      pp.post_proc_flag = VP8_DEBLOCK | VP8_DEMACROBLOCK;
      pp.deblocking_level = 8;
      vpx_codec_control(codec, VP8_SET_POSTPROC, &pp);
    }

    // Error details
    if (vpx_codec_error(codec)) {
      const char *error = vpx_codec_error(codec);
      const char *detail = vpx_codec_error_detail(codec);
      (void)error; (void)detail;
    }
  }

  void CleanupDecoders() {
    // Cleanup any persistent decoders
  }

  int iteration_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20 || size > 8 * 1024 * 1024) {
    return 0;
  }

  static thread_local VPXHybridMaxCoverage fuzzer;
  
  fuzzer.FuzzDecode(data, size);

  return 0;
}


