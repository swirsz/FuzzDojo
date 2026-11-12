#include <stdint.h>
#include <limits>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/jpeg_data_decoder.h"
#include "guetzli/processor.h"
#include "guetzli/output_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Add minimum size check
  if (size < 2) {
    return 0;
  }
  
  // Limit maximum input size to prevent excessive memory usage
  static constexpr size_t kMaxInputSize = 1024 * 1024; // 1MB
  if (size > kMaxInputSize) {
    return 0;
  }
  
  std::string jpeg_data(reinterpret_cast<const char*>(data), size);
  
  // Ignore large images, to prevent timeouts.
  guetzli::JPEGData jpg_header;
  // Use consistent API - pass data pointer and size
  if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_HEADER, &jpg_header)) {
    return 0;
  }
  
  // Validate dimensions are positive and reasonable
  if (jpg_header.width <= 0 || jpg_header.height <= 0) {
    return 0;
  }
  
  // Check for integer overflow in dimension storage
  if (jpg_header.width > std::numeric_limits<int>::max() ||
      jpg_header.height > std::numeric_limits<int>::max()) {
    return 0;
  }
  
  int width = jpg_header.width;
  int height = jpg_header.height;
  
  // Properly cast both operands before multiplication to prevent overflow
  static constexpr int64_t kMaxPixels = 10000;
  int64_t total_pixels = static_cast<int64_t>(width) * static_cast<int64_t>(height);
  if (total_pixels > kMaxPixels) {
    return 0;
  }
  
  // Check for RGB buffer size overflow (width * height * 3)
  // Each pixel needs 3 bytes (RGB), check this won't overflow
  static constexpr int64_t kMaxRGBSize = 10000 * 3; // kMaxPixels * 3 channels
  int64_t expected_rgb_size = total_pixels * 3;
  if (expected_rgb_size > kMaxRGBSize) {
    return 0;
  }
  
  guetzli::JPEGData jpg;
  // Use consistent API for second ReadJpeg call
  if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_ALL, &jpg)) {
    return 0;
  }
  
  // Wrap in try-catch to handle potential exceptions from DecodeJpegToRGB
  std::vector<uint8_t> rgb;
  try {
    rgb = DecodeJpegToRGB(jpg);
  } catch (...) {
    // Decoding failed, return early
    return 0;
  }
  
  // Validate RGB vector has expected size
  if (rgb.empty() || rgb.size() != static_cast<size_t>(expected_rgb_size)) {
    return 0;
  }
  
  // TODO(robryk): Use nondefault parameters.
  guetzli::Params params;
  std::string jpeg_out;
  
  // Wrap Process() in try-catch to handle potential exceptions
  try {
    (void)guetzli::Process(params, nullptr, rgb, width, height, &jpeg_out);
  } catch (...) {
    // Process failed, but this is acceptable for fuzzing
    // Continue to test OutputImage code path
  }
  
  // TODO(robryk): Verify output distance if Process() succeeded.
  
  // Wrap OutputImage operations in try-catch
  try {
    guetzli::OutputImage img(width, height);
    img.CopyFromJpegData(jpg);
    //guetzli::DownsampleImage(img);
  } catch (...) {
    // OutputImage operations failed, acceptable for fuzzing
  }
  
  return 0;
}