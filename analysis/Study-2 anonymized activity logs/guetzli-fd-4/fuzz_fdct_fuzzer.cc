#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "guetzli/jpeg_data.h"
#include "guetzli/fdct.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

  if (size < 128)
      return 0;

  guetzli::coeff_t *coeffs = new guetzli::coeff_t[128];
  for (int i = 0; i < 128; i++) {
    coeffs[i] = fdp.ConsumeIntegral<uint16_t>();
  }


  guetzli::ComputeBlockDCT((guetzli::coeff_t *)coeffs);

  return 0;
}




