#include <stdint.h>
#include <algorithm>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include "guetzli/preprocess_downsample.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size check
  if (size < 10) {
    return 0;
  }

  // Test 1: Process as JPEG data
  std::string jpeg_data(reinterpret_cast<const char*>(data), size);
  
  // Read and validate JPEG header
  guetzli::JPEGData jpg_header;
  if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_HEADER, &jpg_header)) {
    return 0;
  }
  
  // Ignore large images to prevent timeouts
  static constexpr int kMaxPixels = 10000;
  static constexpr int kMaxDimension = 1000;
  
  if (static_cast<int64_t>(jpg_header.width) * jpg_header.height > kMaxPixels ||
      jpg_header.width > kMaxDimension || jpg_header.height > kMaxDimension ||
      jpg_header.width <= 0 || jpg_header.height <= 0) {
    return 0;
  }

  // Process with default parameters
  guetzli::Params params;
  std::string jpeg_out;
  (void)guetzli::Process(params, nullptr, jpeg_data, &jpeg_out);

  // Test 2: Process as RGB data with synthesized dimensions
  // Use first few bytes to determine small dimensions
  if (size >= 20) {
    // Extract small dimensions from fuzz input
    int width = (data[0] % 10) + 1;  // 1-10
    int height = (data[1] % 10) + 1; // 1-10
    int required_size = width * height * 3;
    
    // Only proceed if we have enough data
    if (required_size <= static_cast<int>(size - 2)) {
      std::vector<uint8_t> rgb_data(data + 2, data + 2 + required_size);
      (void)guetzli::Process(params, nullptr, rgb_data, width, height, &jpeg_out);
      
      // Test 3: RGB to YUV conversion with valid dimensions
      try {
        std::vector<std::vector<float>> yuv = 
            guetzli::RGBToYUV420(rgb_data, width, height);
      } catch (...) {
        // Catch any exceptions from processing
        return 0;
      }
    }
  }

  return 0;
}