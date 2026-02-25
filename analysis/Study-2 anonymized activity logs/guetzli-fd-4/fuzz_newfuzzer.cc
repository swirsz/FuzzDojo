#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_decoder.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/processor.h"
#include "guetzli/preprocess_downsample.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);


    std::string jpeg_data(reinterpret_cast<const char*>(data), size);

    // Ignore large images, to prevent timeouts.
    guetzli::JPEGData jpg;
    if (!guetzli::ReadJpeg(data, size, guetzli::JPEG_READ_ALL, &jpg)) {
      return 0;
    }

    static constexpr int kMaxPixels = 10000;
    if (static_cast<int64_t>(jpg.width) * jpg.height > kMaxPixels) {
      return 0;
    }

    std::vector<uint8_t> rgb = guetzli::DecodeJpegToRGB(jpg);
    if (rgb.empty()) {
      return 0;
    }


    // std::vector<std::vector<float>> RGBToYUV420( const std::vector<uint8_t>& rgb_in, const int width, const int height);
    const std::vector<std::vector<float>> rgb_2d = guetzli::RGBToYUV420(rgb, jpg.width, jpg.height);

    // Select value between 1 or 2
    int channel = (data[0] & 1) + 1;
    float amount = fdp.ConsumeFloatingPointInRange(0.0f, 1.0f);
    float sigma = fdp.ConsumeFloatingPointInRange(-3.0f, 3.0f);
    bool blur = fdp.ConsumeBool();
    bool sharpen = !blur;


    // std::vector<std::vector<float>> PreProcessChannel( int w, int h, int channel, float sigma, float amount, bool blur, bool sharpen, const std::vector<std::vector<float>>& image);
    std::vector<std::vector<float>> pp_rgb = guetzli::PreProcessChannel( jpg.width, jpg.height, channel, sigma, amount, blur, sharpen, rgb_2d);

    /*
      // TODO(robryk): Use nondefault parameters.
      // guetzli::Params params;
      // std::string jpeg_out;
      // (void)guetzli::Process(params, nullptr, jpeg_data, &jpeg_out);
      // TODO(robryk): Verify output distance if Process() succeeded.
    */
    return 0;
}
