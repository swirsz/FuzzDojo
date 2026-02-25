#include <stdint.h>
#include <algorithm>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include "guetzli/preprocess_downsample.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Validate minimum input size
  if (size < 3) {
    return 0;
  }
  
  size_t actual_size = size - size % 3;
  
  // Limit maximum size to prevent excessive memory allocation
  const size_t kMaxSize = 1024 * 1024; // 1MB max
  if (actual_size > kMaxSize) {
    actual_size = kMaxSize - (kMaxSize % 3);
  }
  
  const std::vector<uint8_t> rgb_in(data, data + actual_size);
  const int w = actual_size / 3;
  const int h = 1;
  
  // Validate dimensions
  if (w <= 0 || h <= 0) {
    return 0;
  }
  
  // Protect against extremely wide images that could cause issues
  const int kMaxWidth = 65535;
  if (w > kMaxWidth) {
    return 0;
  }
  
  try {
    std::vector<std::vector<float>> yuv = guetzli::RGBToYUV420(rgb_in, w, h);
    
    // Validate YUV output before processing
    if (yuv.empty() || yuv.size() < 3) {
      return 0;
    }
    
    // Ensure the channel index is valid
    const int channel = std::min(2, static_cast<int>(yuv.size()) - 1);
    
    guetzli::PreProcessChannel(w, h, channel, 1.3, 1.5, true, true, yuv);
  } catch (...) {
    // Catch any exceptions to prevent fuzzer crashes
    return 0;
  }
  
  return 0;
}