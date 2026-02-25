#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"     // VP9 decoder iface + VP9D_* controls
#include "vpx/vpx_image.h"
}

// ---------------- IVF helpers (VP9 "VP90") ----------------

static bool IsIvfVp9(const uint8_t* data, size_t size) {
  // IVF header: 32 bytes. Magic "DKIF" at 0..3, fourcc "VP90" at 8..11.
  if (!data || size < 32) return false;
  if (!(data[0]=='D' && data[1]=='K' && data[2]=='I' && data[3]=='F')) return false;
  return (data[8]=='V' && data[9]=='P' && data[10]=='9' && data[11]=='0');
}

static bool ParseIvfFrame(const uint8_t* data, size_t size,
                          size_t* off, const uint8_t** frame_ptr, size_t* frame_sz) {
  if (*off + 12 > size) return false;
  uint32_t fs = (uint32_t)data[*off] |
                ((uint32_t)data[*off + 1] << 8) |
                ((uint32_t)data[*off + 2] << 16) |
                ((uint32_t)data[*off + 3] << 24);
  *off += 12;  // skip size (4) + pts (8)
  if (*off + fs > size) return false;
  *frame_ptr = data + *off;
  *frame_sz = fs;
  *off += fs;
  return true;
}

// ---------------- Fuzzer entry ----------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size == 0) return 0;

  // A few config bytes to vary behavior without heavy parsing.
  const uint8_t b0 = data[0];
  const uint8_t b1 = (size > 1) ? data[1] : 0;

  // Init VP9 decoder with >1 thread to actually engage row-MT.
  vpx_codec_ctx_t ctx;
  std::memset(&ctx, 0, sizeof(ctx));

  vpx_codec_dec_cfg_t cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.w = 0;
  cfg.h = 0;
  // 2..8 threads; keep bounded for stability.
  cfg.threads = 2 + (b0 & 0x7);  // 2..9 but lib may clamp internally

  if (vpx_codec_dec_init(&ctx, vpx_codec_vp9_dx(), &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // Enable row-based multi-threading; optionally enable loop-filter optimization.
  // These are public decoder controls; errors are ignored so fuzzing can continue.
  int on = 1;
  (void)vpx_codec_control(&ctx, VP9D_SET_ROW_MT, on);

  if (b1 & 0x1) {
    (void)vpx_codec_control(&ctx, VP9D_SET_LOOP_FILTER_OPT, on);
  }

  // Decode IVF multi-frame or treat input as a single compressed frame.
  if (IsIvfVp9(data, size)) {
    size_t off = 32;
    const uint8_t* frame_ptr = nullptr;
    size_t frame_sz = 0;

    int frames = 0;
    while (frames < 100 && ParseIvfFrame(data, size, &off, &frame_ptr, &frame_sz)) {
      (void)vpx_codec_decode(&ctx, frame_ptr, static_cast<unsigned int>(frame_sz), nullptr, 0);

      // Drain frames to run post-decode + LF paths and keep workers busy.
      vpx_codec_iter_t it = nullptr;
      vpx_image_t* img = nullptr;
      while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
        volatile int w = img->d_w;
        volatile int h = img->d_h;
        (void)w; (void)h;
      }
      frames++;
    }
  } else {
    (void)vpx_codec_decode(&ctx, data, static_cast<unsigned int>(size), nullptr, 0);
    vpx_codec_iter_t it = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
      volatile int w = img->d_w;
      volatile int h = img->d_h;
      (void)w; (void)h;
    }
  }

  // Final flush tick (covers a small branch in the plumbing).
  (void)vpx_codec_decode(&ctx, nullptr, 0, nullptr, 0);

  vpx_codec_destroy(&ctx);
  return 0;
}

/*
 * Fuzzer for libvpx VP9 decoder control: ctrl_set_reference
 *
 * Targets the decoder control map entry:
 *   { VP8_SET_REFERENCE, ctrl_set_reference }
 *
 * References:
 * - ctrl_set_reference implementation (image2yuvconfig + vp9_set_reference_dec)
 *   https://chromium.googlesource.com/webm/libvpx/+/master/vp9/vp9_dx_iface.c
 *
 * Build: gets compiled by OSS-Fuzz with libFuzzer and libvpx decoder.
 */

#include <cstdint>
#include <cstddef>
#include <algorithm>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"      // vpx_codec_iface_t for decoders (VP9)
#include "vpx/vp8.h"        // vpx_ref_frame_t, VP8_* reference enums
#include "vpx/vpx_image.h"  // vpx_img_alloc/free
}

static inline uint32_t ReadLE32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create decoder context
  vpx_codec_ctx_t dec;
  if (vpx_codec_dec_init(&dec, vpx_codec_vp9_dx(), /*cfg=*/nullptr, /*flags=*/0) != VPX_CODEC_OK) {
    return 0;
  }

  // Split the input:
  // - First slice initializes the decoder (must be non-empty so init path runs).
  // - Remainder populates a reference image we set via VP8_SET_REFERENCE.
  const size_t init_bytes = std::min<size_t>(size, 64);
  const uint8_t *init_data = data;
  const size_t init_size = init_bytes ? init_bytes : 1; // ensure non-zero
  uint8_t dummy = 0;
  if (init_bytes == 0) init_data = &dummy;

  // Feed some bytes so the decoder calls init_decoder() and creates ctx->pbi
  // (decoder_decode() initializes when pbi==NULL and data != NULL). :contentReference[oaicite:1]{index=1}
  (void)vpx_codec_decode(&dec, init_data, static_cast<unsigned int>(init_size), /*user_priv=*/nullptr, /*deadline=*/0);

  // Try to query frame size; if not available, derive bounded dims from fuzzer input.
  int frame_size_q[2] = {0, 0};
  if (vpx_codec_control(&dec, VP9D_GET_FRAME_SIZE, frame_size_q) != VPX_CODEC_OK ||
      frame_size_q[0] <= 0 || frame_size_q[1] <= 0) {
    // Make a small, safe canvas to avoid huge allocations.
    // Use a few bytes of the remaining input to pick dimensions.
    const uint8_t *p = data + init_bytes;
    size_t rem = (size > init_bytes) ? (size - init_bytes) : 0;

    uint32_t w = 16, h = 16;
    if (rem >= 8) {
      w = 1 + (ReadLE32(p) % 64);      // 1..64
      h = 1 + (ReadLE32(p + 4) % 64);  // 1..64
    }
    frame_size_q[0] = static_cast<int>(w);
    frame_size_q[1] = static_cast<int>(h);
  }

  // Allocate an I420 image for the reference frame.
  const int width = std::max(1, std::min(frame_size_q[0], 256));
  const int height = std::max(1, std::min(frame_size_q[1], 256));
  vpx_image_t img;
  if (!vpx_img_alloc(&img, VPX_IMG_FMT_I420, width, height, /*align=*/32)) {
    vpx_codec_destroy(&dec);
    return 0;
  }

  // Fill image planes with whatever remains from the fuzzer input (repeat if short).
  const uint8_t *payload = data + init_bytes;
  size_t payload_len = (size > init_bytes) ? (size - init_bytes) : 0;
  auto fill_plane = [&](uint8_t *dst, int stride, int w, int h) {
    size_t need = static_cast<size_t>(stride) * static_cast<size_t>(h);
    size_t off = 0;
    while (off < need) {
      if (payload_len == 0) {
        // deterministic filler when out of bytes
        dst[off++] = static_cast<uint8_t>((off * 131u) ^ 0x5A);
      } else {
        size_t chunk = std::min(need - off, payload_len);
        std::memcpy(dst + off, payload, chunk);
        off += chunk;
        // Move window forward but keep at least some variability across planes
        size_t advance = std::min(chunk, payload_len);
        payload += advance;
        payload_len -= advance;
      }
    }
  };
  // Y plane
  fill_plane(img.planes[0], img.stride[0], img.d_w, img.d_h);
  // U/V planes (I420 -> half resolution)
  fill_plane(img.planes[1], img.stride[1], (img.d_w + 1) / 2, (img.d_h + 1) / 2);
  fill_plane(img.planes[2], img.stride[2], (img.d_w + 1) / 2, (img.d_h + 1) / 2);

  // Choose a reference slot.
  // vpx_ref_frame_type_t is VP8_{LAST,GOLD,ALTR}_FRAME with values {1,2,4}. :contentReference[oaicite:2]{index=2}
  vpx_ref_frame_t ref{};
  const uint8_t tag = (size > 0) ? data[size - 1] : 0;
  switch (tag % 3) {
    case 0: ref.frame_type = VP8_LAST_FRAME; break;
    case 1: ref.frame_type = VP8_GOLD_FRAME; break;
    default: ref.frame_type = VP8_ALTR_FRAME; break;
  }
  ref.img = img;

  // Invoke the control that maps to ctrl_set_reference:
  //   image2yuvconfig(&frame->img, &sd);
  //   return vp9_set_reference_dec(&ctx->pbi->common, ref_frame_to_vp9_reframe(...), &sd);
  // This requires ctx->pbi to be non-null, hence the earlier decode call. :contentReference[oaicite:3]{index=3}
  (void)vpx_codec_control(&dec, VP8_SET_REFERENCE, &ref);

  vpx_img_free(&img);
  vpx_codec_destroy(&dec);
  return 0;
}

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"     // vpx_codec_vp8_dx, vp8_postproc_cfg_t, VP8_* flags
#include "vpx/vpx_image.h"
}

// ---------- Minimal IVF helpers (VP8 "VP80") ----------

static bool IsIvfVp8(const uint8_t* data, size_t size) {
  if (size < 32) return false;
  // "DKIF"
  if (!(data[0]=='D' && data[1]=='K' && data[2]=='I' && data[3]=='F')) return false;
  // fourcc "VP80"
  return (data[8]=='V' && data[9]=='P' && data[10]=='8' && data[11]=='0');
}

static bool ParseIvfFrame(const uint8_t* data, size_t size,
                          size_t* off, const uint8_t** frame_ptr, size_t* frame_sz) {
  if (*off + 12 > size) return false;
  uint32_t fs = (uint32_t)data[*off] |
                ((uint32_t)data[*off + 1] << 8) |
                ((uint32_t)data[*off + 2] << 16) |
                ((uint32_t)data[*off + 3] << 24);
  *off += 12;  // skip <size><pts>
  if (*off + fs > size) return false;
  *frame_ptr = data + *off;
  *frame_sz = fs;
  *off += fs;
  return true;
}

// ---------- Fuzzer entry ----------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size == 0) return 0;

  // Light config bytes
  const uint8_t b0 = data[0];
  const uint8_t b1 = (size > 1) ? data[1] : 0;
  const uint8_t b2 = (size > 2) ? data[2] : 0;

  // Init VP8 decoder
  vpx_codec_ctx_t ctx;
  std::memset(&ctx, 0, sizeof(ctx));

  vpx_codec_dec_cfg_t cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.w = 0; cfg.h = 0;
  cfg.threads = 1 + (b0 & 0x3); // 1..4 threads

  if (vpx_codec_dec_init(&ctx, vpx_codec_vp8_dx(), &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // ---- Enable postproc with MFQE (core requirement) ----
  vp8_postproc_cfg_t pp;
  std::memset(&pp, 0, sizeof(pp));
  // Always include MFQE; optionally combine with other features to hit more branches.
  pp.post_proc_flag = VP8_MFQE
                    | ((b0 & 0x10) ? VP8_DEBLOCK       : 0)
                    | ((b0 & 0x20) ? VP8_DEMACROBLOCK  : 0)
                    | ((b0 & 0x40) ? VP8_ADDNOISE      : 0);
  pp.deblocking_level = (b1 % 9); // 0..8
  pp.noise_level      = (b2 % 4); // 0..3
  (void)vpx_codec_control(&ctx, VP8_SET_POSTPROC, &pp);

  // Flip MFQE once mid-stream to tick reconfig paths.
  const bool flip_mfqe = (b2 & 0x80) != 0;

  auto drain_frames = [&]() {
    vpx_codec_iter_t it = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
      // Touch a few fields; MFQE operates on decoded output.
      volatile int w = img->d_w;
      volatile int h = img->d_h;
      (void)w; (void)h;
    }
  };

  if (IsIvfVp8(data, size)) {
    size_t off = 32;
    const uint8_t* frame_ptr = nullptr;
    size_t frame_sz = 0;

    int frames = 0;
    while (frames < 120 && ParseIvfFrame(data, size, &off, &frame_ptr, &frame_sz)) {
      (void)vpx_codec_decode(&ctx, frame_ptr, static_cast<unsigned int>(frame_sz), nullptr, 0);
      drain_frames();

      // Toggle MFQE flag after a few frames to exercise dynamic path changes.
      if (flip_mfqe && frames == 2) {
        vp8_postproc_cfg_t pp2 = pp;
        pp2.post_proc_flag ^= VP8_MFQE; // flip MFQE on/off
        (void)vpx_codec_control(&ctx, VP8_SET_POSTPROC, &pp2);
      }
      frames++;
    }
  } else {
    // Treat entire buffer as a single compressed frame (MFQE will be a no-op
    // until a subsequent frame arrives; still useful for control coverage).
    (void)vpx_codec_decode(&ctx, data, static_cast<unsigned int>(size), nullptr, 0);
    drain_frames();
  }

  // Final flush to cover plumbing branches.
  (void)vpx_codec_decode(&ctx, nullptr, 0, nullptr, 0);
  vpx_codec_destroy(&ctx);
  return 0;
}

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>

extern "C" {
// Generated build config (in ${build_dir})
#include "vpx_config.h"

// Basic integer types
#include "vpx/vpx_integer.h"

// Generated runtime-dispatch tables (in ${build_dir})
#include "vpx_dsp_rtcd.h"
#include "vp8_rtcd.h"
}

static inline uint32_t rd32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

template <typename T>
static void fill_from_data(T* dst, size_t n, const uint8_t* data, size_t& off, size_t size) {
  for (size_t i = 0; i < n; ++i) {
    if (off >= size) off = 0;
    dst[i] = static_cast<T>(data[off++]);
  }
}

// Return a subpel offset in [1..7] (never 0) to satisfy SSE2 preconditions.
static inline int subpel_nonzero(uint8_t b) {
  return (int)(b % 7) + 1; // 1..7
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
#if !CONFIG_VP8
  (void)data; (void)size;
  return 0;  // VP8 disabled in this build
#else
  if (!data || size < 8) return 0;

#if CONFIG_RUNTIME_CPU_DETECT
  // Initialize RTCD tables once.
  static bool rtcd_inited = false;
  if (!rtcd_inited) {
    vpx_dsp_rtcd();
    vp8_rtcd();
    rtcd_inited = true;
  }
#endif

  size_t off = 0;
  const uint32_t seed = rd32(data); off += 4;

  // Destination canvas big enough for 16x16 blocks with comfortable stride.
  constexpr int W = 64, H = 64;
  static uint8_t dst[H * W];
  fill_from_data(dst, H * W, data, off, size);
  const int dst_stride = W;

  // Create a larger source plane to allow arbitrary subpel offsets (need padding).
  // Keep an 8px safety margin for 6-tap filters in any direction.
  constexpr int MARGIN = 8;
  constexpr int SW = 96, SH = 96;
  static uint8_t src[SH * SW];
  fill_from_data(src, SH * SW, data, off, size);
  const int src_stride = SW;

  // Choose a few top-left positions (ensure in-bounds for all block sizes and margins).
  const int base_x = (seed & 0x1F);         // 0..31
  const int base_y = ((seed >> 5) & 0x1F);  // 0..31

  // Clamp TL positions so we always have room in src/dst for the largest block (16x16)
  // and an extra margin for filter taps.
  const int s_x = std::max(MARGIN, std::min(base_x, SW - (16 + MARGIN)));
  const int s_y = std::max(MARGIN, std::min(base_y, SH - (16 + MARGIN)));
  const int d_x = std::min(base_x, W  - 16);
  const int d_y = std::min(base_y, H  - 16);

  uint8_t* s_ptr = &src[s_y * src_stride + s_x];
  uint8_t* d_ptr = &dst[d_y * dst_stride + d_x];

  // Choose offsets from data to vary subpel positions and block choices.
  // IMPORTANT: never pass both offsets zero to SSE2 bilinear/sixtap kernels.
  const int xo0 = subpel_nonzero(data[off++]);
  const int yo0 = subpel_nonzero(data[off++]);
  const int xo1 = subpel_nonzero(data[off++]);
  const int yo1 = subpel_nonzero(data[off++]);

  // Helper lambdas to call prediction functions when available.
  auto call_bilin_16x16 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_bilinear_predict16x16
    vp8_bilinear_predict16x16(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_bilin_8x8 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_bilinear_predict8x8
    vp8_bilinear_predict8x8(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_bilin_8x4 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_bilinear_predict8x4
    vp8_bilinear_predict8x4(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_bilin_4x4 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_bilinear_predict4x4
    vp8_bilinear_predict4x4(s, sstride, xo, yo, d, dstride);
#endif
  };

  auto call_sixtap_16x16 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_sixtap_predict16x16
    vp8_sixtap_predict16x16(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_sixtap_8x8 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_sixtap_predict8x8
    vp8_sixtap_predict8x8(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_sixtap_8x4 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_sixtap_predict8x4
    vp8_sixtap_predict8x4(s, sstride, xo, yo, d, dstride);
#endif
  };
  auto call_sixtap_4x4 = [&](uint8_t* s, int sstride, int xo, int yo, uint8_t* d, int dstride) {
#ifdef vp8_sixtap_predict4x4
    vp8_sixtap_predict4x4(s, sstride, xo, yo, d, dstride);
#endif
  };

  // Call a mix of bilinear & sixtap predictors across block sizes with two different subpel pairs.
  // These cover the 1-D horizontal/vertical + 2-D separable filter paths in vp8/common/filter.c.

  // --- 16x16 ---
  call_bilin_16x16 (s_ptr, src_stride, xo0, yo0, d_ptr, dst_stride);
  call_sixtap_16x16(s_ptr, src_stride, xo1, yo1, d_ptr, dst_stride);

  // --- 8x8 (two tiles to vary addresses/strides a bit) ---
  call_bilin_8x8 (s_ptr,                 src_stride, xo1, yo0, d_ptr,                 dst_stride);
  call_sixtap_8x8(s_ptr + 8,             src_stride, xo0, yo1, d_ptr + 8,             dst_stride);

  // --- 8x4 (top and below to cross row boundaries) ---
  call_bilin_8x4 (s_ptr,                 src_stride, xo0, yo1, d_ptr,                 dst_stride);
  call_sixtap_8x4(s_ptr + 4 * src_stride,src_stride, xo1, yo0, d_ptr + 4 * dst_stride,dst_stride);

  // --- 4x4 (several small blocks) ---
  call_bilin_4x4 (s_ptr + 12 + 12*src_stride, src_stride, xo1, yo1,
                  d_ptr + 12 + 12*dst_stride, dst_stride);
  call_sixtap_4x4(s_ptr + 16 +  0*src_stride, src_stride, xo0, yo0,
                  d_ptr + 16 +  0*dst_stride, dst_stride);

  // Read back a few bytes so the calls can't be optimized away.
  volatile uint32_t checksum = 0;
  for (int i = 0; i < 16; ++i) checksum += d_ptr[i];
  (void)checksum;

  return 0;
#endif  // CONFIG_VP8
}

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


