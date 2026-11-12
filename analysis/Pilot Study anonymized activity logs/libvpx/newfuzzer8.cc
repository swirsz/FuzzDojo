/*
 * Copyright (c) 2025 The libvpx project authors. All Rights Reserved.
 *
 * VP9 Decoder Feature Coverage Maximizer
 * Goal: Hit as many code paths as possible by exercising all decoder features
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

// Include post-processing
#if CONFIG_VP9_POSTPROC || !defined(CONFIG_VP9_POSTPROC)
#include "vpx/vp8.h"
#endif

namespace {

// Decode modes for maximum coverage
enum DecodeMode {
  DECODE_NORMAL = 0,           // Standard decode
  DECODE_WITH_POSTPROC,        // Post-processing enabled
  DECODE_SKIP_SOME,            // Skip some frames
  DECODE_PEEK_ONLY,            // Use peek API
  DECODE_WITH_DEADLINE,        // Use different deadlines
  DECODE_LOWRES,               // Low resolution decode
  DECODE_GET_FRAME_MULTI,      // Call get_frame multiple times
  DECODE_MODE_MAX
};

// Post-processing configurations
enum PostProcMode {
  PP_NONE = 0,
  PP_DEBLOCK_ONLY,
  PP_DEMACROBLOCK_ONLY,
  PP_DEBLOCK_DEMACROBLOCK,
  PP_ADDNOISE,
  PP_ALL,
  PP_MAX
};

// Control operations to exercise
enum ControlMode {
  CTRL_MINIMAL = 0,
  CTRL_QUERY_ALL,              // Query all status
  CTRL_POSTPROC_VARIED,        // Vary post-proc settings
  CTRL_BUFFER_OPS,             // Buffer operations
  CTRL_DISPLAY_SIZE,           // Size queries
  CTRL_MAX
};

class VP9CoverageMaximizer {
 public:
  VP9CoverageMaximizer() : frame_count_(0) {}
  
  ~VP9CoverageMaximizer() {
    for (auto* ctx : decoders_) {
      if (ctx) {
        vpx_codec_destroy(ctx);
        delete ctx;
      }
    }
  }

  void FuzzDecode(const uint8_t *data, size_t size) {
    if (size < 8) return;

    // Extract configuration from input
    DecodeMode decode_mode = static_cast<DecodeMode>(data[0] % DECODE_MODE_MAX);
    PostProcMode pp_mode = static_cast<PostProcMode>(data[1] % PP_MAX);
    ControlMode ctrl_mode = static_cast<ControlMode>(data[2] % CTRL_MAX);
    uint8_t thread_count = (data[3] % 8) + 1;  // 1-8 threads
    bool use_frame_parallel = (data[4] & 0x01);
    bool use_lowres = (data[4] & 0x02);
    uint8_t skip_pattern = data[5];
    
    // VP9 data starts at offset 6
    const uint8_t *vp9_data = data + 6;
    size_t vp9_size = size - 6;

    // Create decoder with specific configuration
    vpx_codec_ctx_t* codec = CreateDecoder(thread_count, use_frame_parallel, use_lowres);
    if (!codec) return;

    // Configure post-processing
    ConfigurePostProcessing(codec, pp_mode);

    // Decode with specific mode
    switch (decode_mode) {
      case DECODE_NORMAL:
        DecodeNormal(codec, vp9_data, vp9_size, ctrl_mode);
        break;
      case DECODE_WITH_POSTPROC:
        DecodeWithPostProc(codec, vp9_data, vp9_size, pp_mode);
        break;
      case DECODE_SKIP_SOME:
        DecodeWithSkip(codec, vp9_data, vp9_size, skip_pattern);
        break;
      case DECODE_PEEK_ONLY:
        DecodePeekOnly(codec, vp9_data, vp9_size);
        break;
      case DECODE_WITH_DEADLINE:
        DecodeWithDeadline(codec, vp9_data, vp9_size, data[4]);
        break;
      case DECODE_LOWRES:
        DecodeLowRes(codec, vp9_data, vp9_size);
        break;
      case DECODE_GET_FRAME_MULTI:
        DecodeMultiGet(codec, vp9_data, vp9_size);
        break;
      default:
        DecodeNormal(codec, vp9_data, vp9_size, ctrl_mode);
        break;
    }

    // Exercise control operations
    ExerciseControls(codec, ctrl_mode);

    // Cleanup
    vpx_codec_destroy(codec);
    delete codec;

    frame_count_++;
  }

 private:
  vpx_codec_ctx_t* CreateDecoder(int threads, bool frame_parallel, bool lowres) {
    vpx_codec_ctx_t* codec = new vpx_codec_ctx_t;
    memset(codec, 0, sizeof(*codec));

    vpx_codec_dec_cfg_t cfg = {0};
    cfg.threads = threads;
    cfg.w = 0;
    cfg.h = 0;

    int flags = 0;
    if (frame_parallel) {
      flags |= VPX_CODEC_USE_FRAME_THREADING;
    }

    vpx_codec_err_t res = vpx_codec_dec_init(
        codec, vpx_codec_vp9_dx(), &cfg, flags);
    
    if (res != VPX_CODEC_OK) {
      delete codec;
      return nullptr;
    }

    return codec;
  }

  void ConfigurePostProcessing(vpx_codec_ctx_t* codec, PostProcMode mode) {
    if (!codec) return;

    vp8_postproc_cfg_t pp_cfg;
    memset(&pp_cfg, 0, sizeof(pp_cfg));

    switch (mode) {
      case PP_NONE:
        pp_cfg.post_proc_flag = 0;
        break;
      case PP_DEBLOCK_ONLY:
        pp_cfg.post_proc_flag = VP8_DEBLOCK;
        pp_cfg.deblocking_level = 5;
        break;
      case PP_DEMACROBLOCK_ONLY:
        pp_cfg.post_proc_flag = VP8_DEMACROBLOCK;
        break;
      case PP_DEBLOCK_DEMACROBLOCK:
        pp_cfg.post_proc_flag = VP8_DEBLOCK | VP8_DEMACROBLOCK;
        pp_cfg.deblocking_level = 8;
        break;
      case PP_ADDNOISE:
        pp_cfg.post_proc_flag = VP8_ADDNOISE;
        break;
      case PP_ALL:
        pp_cfg.post_proc_flag = VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_ADDNOISE;
        pp_cfg.deblocking_level = 10;
        break;
      default:
        pp_cfg.post_proc_flag = 0;
        break;
    }

    vpx_codec_control(codec, VP8_SET_POSTPROC, &pp_cfg);
  }

  void DecodeNormal(vpx_codec_ctx_t* codec, const uint8_t* data, 
                   size_t size, ControlMode ctrl_mode) {
    if (!codec || size == 0) return;

    vpx_codec_decode(codec, data, size, nullptr, 0);

    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
      AccessFrameData(img);
      if (ctrl_mode == CTRL_QUERY_ALL) {
        QueryAllStatus(codec);
      }
    }
  }

  void DecodeWithPostProc(vpx_codec_ctx_t* codec, const uint8_t* data,
                         size_t size, PostProcMode mode) {
    if (!codec || size == 0) return;

    // Vary post-proc settings during decode
    for (int level = 0; level < 3; level++) {
      vp8_postproc_cfg_t pp_cfg;
      pp_cfg.post_proc_flag = VP8_DEBLOCK;
      pp_cfg.deblocking_level = level * 5;
      vpx_codec_control(codec, VP8_SET_POSTPROC, &pp_cfg);
    }

    vpx_codec_decode(codec, data, size, nullptr, 0);

    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
      AccessFrameData(img);
    }
  }

  void DecodeWithSkip(vpx_codec_ctx_t* codec, const uint8_t* data,
                     size_t size, uint8_t skip_pattern) {
    if (!codec || size == 0) return;

    // Simulate skipping frames based on pattern
    bool should_skip = (frame_count_ % 4) == (skip_pattern % 4);
    
    unsigned int flags = should_skip ? VPX_CODEC_USE_INPUT_FRAGMENTS : 0;
    
    vpx_codec_decode(codec, data, size, nullptr, flags);

    if (!should_skip) {
      vpx_codec_iter_t iter = nullptr;
      while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
        AccessFrameData(img);
      }
    }
  }

  void DecodePeekOnly(vpx_codec_ctx_t* codec, const uint8_t* data, size_t size) {
    if (!codec || size == 0) return;

    vpx_codec_decode(codec, data, size, nullptr, 0);

    // Use peek instead of get (different code path)
    vpx_codec_iter_t iter = nullptr;
    if (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
      AccessFrameData(img);
      // Don't iterate further - just peek at first frame
    }
  }

  void DecodeWithDeadline(vpx_codec_ctx_t* codec, const uint8_t* data,
                         size_t size, uint8_t deadline_byte) {
    if (!codec || size == 0) return;

    // Vary deadline to hit different decode paths
    long deadline = 0;
    switch (deadline_byte % 4) {
      case 0: deadline = 0; break;              // Best quality
      case 1: deadline = 1000; break;           // Good quality
      case 2: deadline = 1000000; break;        // Realtime
      case 3: deadline = 1; break;              // Fastest/realtime
    }

    vpx_codec_decode(codec, data, size, nullptr, deadline);

    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
      AccessFrameData(img);
    }
  }

  void DecodeLowRes(vpx_codec_ctx_t* codec, const uint8_t* data, size_t size) {
    if (!codec || size == 0) return;

    vpx_codec_decode(codec, data, size, nullptr, 0);

    vpx_codec_iter_t iter = nullptr;
    while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
      AccessFrameData(img);
    }
  }

  void DecodeMultiGet(vpx_codec_ctx_t* codec, const uint8_t* data, size_t size) {
    if (!codec || size == 0) return;

    vpx_codec_decode(codec, data, size, nullptr, 0);

    // Call get_frame multiple times with same iterator
    for (int attempt = 0; attempt < 3; attempt++) {
      vpx_codec_iter_t iter = nullptr;
      while (vpx_image_t* img = vpx_codec_get_frame(codec, &iter)) {
        AccessFrameData(img);
        break;  // Only get first frame each attempt
      }
    }
  }

  void AccessFrameData(vpx_image_t* img) {
    if (!img || img->d_w == 0 || img->d_h == 0) return;

    // Touch all planes (Y, U, V or Y, U, V, A for alpha)
    for (int plane = 0; plane < 3; plane++) {
      if (img->planes[plane] && img->stride[plane] > 0) {
        // Calculate plane dimensions based on format
        int w = (plane == 0) ? img->d_w : ((img->d_w + 1) >> 1);
        int h = (plane == 0) ? img->d_h : ((img->d_h + 1) >> 1);
        
        if (w > 0 && h > 0) {
          // Touch corners and center
          volatile uint8_t tl = img->planes[plane][0];
          
          if (w > 1) {
            volatile uint8_t tr = img->planes[plane][w - 1];
            (void)tr;
          }
          
          if (h > 1 && img->stride[plane] * (h - 1) < img->stride[plane] * h) {
            volatile uint8_t bl = img->planes[plane][img->stride[plane] * (h - 1)];
            (void)bl;
            
            if (w > 1) {
              volatile uint8_t br = img->planes[plane][img->stride[plane] * (h - 1) + w - 1];
              (void)br;
            }
          }
          
          (void)tl;
        }
      }
    }

    // Check for alpha plane
    if (img->fmt & VPX_IMG_FMT_HAS_ALPHA) {
      if (img->planes[VPX_PLANE_ALPHA]) {
        volatile uint8_t alpha = img->planes[VPX_PLANE_ALPHA][0];
        (void)alpha;
      }
    }
  }

  void ExerciseControls(vpx_codec_ctx_t* codec, ControlMode mode) {
    if (!codec) return;

    switch (mode) {
      case CTRL_MINIMAL:
        // Just check error
        if (vpx_codec_error(codec)) {
          const char* detail = vpx_codec_error_detail(codec);
          (void)detail;
        }
        break;

      case CTRL_QUERY_ALL:
        QueryAllStatus(codec);
        break;

      case CTRL_POSTPROC_VARIED:
        // Vary post-proc settings
        for (int i = 0; i < 5; i++) {
          vp8_postproc_cfg_t pp;
          pp.post_proc_flag = (i % 2) ? VP8_DEBLOCK : VP8_DEMACROBLOCK;
          pp.deblocking_level = i * 3;
          vpx_codec_control(codec, VP8_SET_POSTPROC, &pp);
        }
        break;

      case CTRL_BUFFER_OPS:
        QueryBufferInfo(codec);
        break;

      case CTRL_DISPLAY_SIZE:
        QuerySizeInfo(codec);
        break;

      default:
        break;
    }
  }

  void QueryAllStatus(vpx_codec_ctx_t* codec) {
    if (!codec) return;

    // Query corruption status
    int corrupted = 0;
    vpx_codec_control(codec, VP8D_GET_FRAME_CORRUPTED, &corrupted);

    // Query various decoder info
    int width = 0, height = 0;
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &width);
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &height);

    // Get bit depth (requires unsigned int*)
    unsigned int bit_depth = 0;
    vpx_codec_control(codec, VP9D_GET_BIT_DEPTH, &bit_depth);

    // Check error details
    if (vpx_codec_error(codec)) {
      const char* detail = vpx_codec_error_detail(codec);
      const char* error = vpx_codec_error(codec);
      (void)detail;
      (void)error;
    }
  }

  void QueryBufferInfo(vpx_codec_ctx_t* codec) {
    if (!codec) return;

    // Query frame buffer info
    int min_fb = 0;
    vpx_codec_control(codec, VP9D_GET_FRAME_SIZE, &min_fb);
  }

  void QuerySizeInfo(vpx_codec_ctx_t* codec) {
    if (!codec) return;

    int width = 0, height = 0;
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &width);
    vpx_codec_control(codec, VP9D_GET_DISPLAY_SIZE, &height);
    
    int frame_size = 0;
    vpx_codec_control(codec, VP9D_GET_FRAME_SIZE, &frame_size);
  }

  std::vector<vpx_codec_ctx_t*> decoders_;
  int frame_count_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 16 || size > 8 * 1024 * 1024) {
    return 0;
  }

  static thread_local VP9CoverageMaximizer fuzzer;
  
  fuzzer.FuzzDecode(data, size);

  return 0;
}


