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

