#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <limits>
#include <cmath>
#include "guetzli/preprocess_downsample.h"

static inline uint8_t rd8(const uint8_t* data, size_t size, size_t& off) {
  uint8_t v = data[off % size]; ++off; return v;
}
static inline uint16_t rd16(const uint8_t* data, size_t size, size_t& off) {
  return (uint16_t(rd8(data,size,off)) << 8) | rd8(data,size,off);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;

  size_t off = 0;
  constexpr int kMaxPixels = 10000;

  // Choose even dims for 4:2:0 conversion, clamp small to avoid long runs.
  int w = 2 + ((rd16(data,size,off) % 64) & ~1); // even, >=2
  int h = 2 + ((rd16(data,size,off) % 64) & ~1); // even, >=2
  if (w * h > kMaxPixels) return 0;

  // sigma in [0, 5], amount in [0, 2]
  float sigma  = (rd8(data,size,off) / 255.0f) * 5.0f;
  float amount = (rd8(data,size,off) / 255.0f) * 2.0f;

  uint8_t flags = rd8(data,size,off);
  bool blur     = (flags & 1) != 0;
  bool sharpen  = (flags & 2) != 0;
  if (!blur && !sharpen) blur = true; // ensure work happens

  // Build a small RGB image and convert to YUV420 using the library helper.
  std::vector<uint8_t> rgb(static_cast<size_t>(w) * h * 3);
  for (auto& b : rgb) b = rd8(data,size,off);

  std::vector<std::vector<float>> yuv = guetzli::RGBToYUV420(rgb, w, h);
  if (yuv.size() != 3 || yuv[0].size() != static_cast<size_t>(w) * h) return 0;

  // The header says PreProcessChannel is for U (1) or V (2).
  try {
    (void)guetzli::PreProcessChannel(w, h, 1, sigma, amount, blur, sharpen, yuv);
    (void)guetzli::PreProcessChannel(w, h, 2, sigma, amount, blur, sharpen, yuv);
  } catch (...) {
    // swallow exceptions to keep fuzzing
  }

  return 0;
}
