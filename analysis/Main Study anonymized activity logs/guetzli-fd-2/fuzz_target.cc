#include <stdint.h>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string jpeg_data(reinterpret_cast<const char*>(data), size);
  FuzzedDataProvider fdp(data, size);
  // Ignore large images, to prevent timeouts.
  guetzli::JPEGData jpg_header;
  if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_HEADER, &jpg_header)) {
    return 0;
  }
  static constexpr int kMaxPixels = 30000;
  if (static_cast<int64_t>(jpg_header.width) * jpg_header.height > kMaxPixels) {
    return 0;
  }

  // TODO(robryk): Use nondefault parameters.
  guetzli::Params params;

  params.butteraugli_target = fdp.ConsumeFloatingPointInRange<float>(0.0f, 5.0f);
  // Randomize boolean flags to toggle metadata paths
  params.clear_metadata = fdp.ConsumeBool();
  std::string jpeg_out;
  (void)guetzli::Process(params, nullptr, jpeg_data, &jpeg_out);
  // TODO(robryk): Verify output distance if Process() succeeded.
  return 0;
}