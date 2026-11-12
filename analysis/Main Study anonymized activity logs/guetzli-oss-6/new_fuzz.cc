#include <stdint.h>

#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include "guetzli/output_image.h"
#include "guetzli/preprocess_downsample.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string jpeg_data(reinterpret_cast<const char*>(data), size);

  // Ignore large images, to prevent timeouts.
  guetzli::JPEGData jpg_header;
  // if (!guetzli::ReadJpeg(jpeg_data, guetzli::JPEG_READ_ALL, &jpg)) {
  if (!guetzli::ReadJpeg(jpeg_data, guetzli::JPEG_READ_HEADER, &jpg_header)) {
    return 0;
  }
  static constexpr int kMaxPixels = 10000;
  const size_t sz = static_cast<int64_t>(jpg_header.width) * jpg_header.height ;
  if (sz > kMaxPixels) {
    return 0;
  }

  // guetzli::OutputImage oimg = guetzli::OutputImage(jpg.width, jpg.height);
  // oimg.CopyFromJpegData(jpg);
    std::vector<uint8_t> rgb(data, data + 3* sz);
    std::vector<std::vector<float> > yuv = guetzli::RGBToYUV420(rgb, jpg_header.width, jpg_header.height);
  yuv = guetzli::PreProcessChannel(jpg_header.width, jpg_header.height, 2, 1.3f, 0.5f,
                          true, true, yuv);
/*
  // TODO(robryk): Use nondefault parameters.
  guetzli::Params params;
  std::string jpeg_out;
  (void)guetzli::Process(params, nullptr, jpeg_data, &jpeg_out);
  // TODO(robryk): Verify output distance if Process() succeeded.
  */
  return 0;
}
