#include <stdint.h>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include "guetzli/preprocess_downsample.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string jpeg_data(reinterpret_cast<const char*>(data), size);
  int rgb_size = size - (size % 18);
  std::vector<uint8_t> jpeg_rgb(data, data + rgb_size);
  // Ignore large images, to prevent timeouts.
  guetzli::JPEGData jpg_header;
  if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_HEADER, &jpg_header)) {
    return 0;
  }
  static constexpr int kMaxPixels = 10000;
  if (static_cast<int64_t>(jpg_header.width) * jpg_header.height > kMaxPixels) {
    return 0;
  }

  // TODO(robryk): Use nondefault parameters.
  guetzli::Params params;
  std::string jpeg_out;
  (void)guetzli::Process(params, nullptr, jpeg_data, &jpeg_out);
  (void)guetzli::Process(params, nullptr, jpeg_rgb, size / 10, 10, &jpeg_out);
  
  std::vector<std::vector<float> > yuv = guetzli::RGBToYUV420(jpeg_rgb, rgb_size / 9, 3);
  guetzli::PreProcessChannel(rgb_size / 9, 3, 2, 1.3f, 0.5f, 1, 1, yuv);
  //guetzli::JPEGData jpg;
  //guetzli::ReadJpeg(jpeg_out, guetzli::JPEG_READ_ALL, &jpg);
  //for (size_t i = 0; i < jpg.components.size(); ++i) {
  //  guetzli::JPEGComponent& comp = jpg.components[i];
  //  comp.h_samp_factor = jpg.max_h_samp_factor;
  //  comp.v_samp_factor = jpg.max_v_samp_factor;
  //}

  //guetzli::OutputImage img(jpg.width, jpg.height);
  //img.CopyFromJpegData(jpg);
  //guetzli::OutputImage::DownsampleConfig cfg;
  //cfg.use_silver_screen = params_.use_silver_screen;
  //img.Downsample(cfg);
  // TODO(robryk): Verify output distance if Process() succeeded.
  return 0;
}
