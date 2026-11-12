#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "guetzli/jpeg_data.h"
#include "guetzli/jpeg_data_encoder.h"
#include "guetzli/jpeg_data_reader.h"
#include "guetzli/jpeg_data_writer.h"
#include "guetzli/jpeg_data_decoder.h"
#include "guetzli/preprocess_downsample.h"
#include "guetzli/output_image.h"
#include "guetzli/dct_double.h"

// ULTIMATE FUZZER - Combines all coverage paths for maximum hit rate
// Targets: dct_double.cc, jpeg_data_decoder.cc, output_image.cc, 
//          preprocess_downsample.cc, fdct.cc, entropy_encode.cc
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) {
    return 0;
  }

  uint8_t mode = data[0];
  
  // ==================== MODE 0-63: Direct DCT Double ====================
  // This GUARANTEES dct_double.cc coverage (currently 0%)
  if (mode < 64) {
    if (size < 64) return 0;
    
    double block[64];
    for (int i = 0; i < 64; ++i) {
      block[i] = static_cast<double>(data[i]) - 128.0;
    }
    
    guetzli::ComputeBlockDCTDouble(block);
    guetzli::ComputeBlockIDCTDouble(block);
    
    // Second block if we have data
    if (size >= 128) {
      for (int i = 0; i < 64; ++i) {
        block[i] = static_cast<double>(data[64 + i]) - 128.0;
      }
      guetzli::ComputeBlockDCTDouble(block);
      guetzli::ComputeBlockIDCTDouble(block);
    }
    return 0;
  }
  
  // ==================== MODE 64-127: Encoder + Decoder + OutputImage ====================
  // Hits: jpeg_data_encoder.cc, fdct.cc, jpeg_data_decoder.cc, output_image.cc
  if (mode < 128) {
    if (size < 20) return 0;
    
    int w = 16 + (data[1] % 48);
    int h = 16 + (data[2] % 48);
    if (w * h > 3000) { w = h = 32; }
    
    std::vector<uint8_t> rgb(w * h * 3);
    for (size_t i = 0; i < rgb.size(); ++i) {
      rgb[i] = data[3 + (i % (size - 3))];
    }
    
    // Encode with custom quantization
    guetzli::JPEGData jpg;
    if (size >= 200) {
      int quant[192];
      for (int i = 0; i < 192; ++i) {
        uint8_t val = data[3 + (i % (size - 3))];
        quant[i] = 1 + (val % 100);
      }
      guetzli::EncodeRGBToJpeg(rgb, w, h, quant, &jpg);
    } else {
      guetzli::EncodeRGBToJpeg(rgb, w, h, &jpg);
    }
    
    // Decode back (hits decoder)
    auto decoded = guetzli::DecodeJpegToRGB(jpg);
    
    if (!decoded.empty()) {
      // OutputImage operations
      guetzli::OutputImage img(w, h);
      img.CopyFromJpegData(jpg);
      
      // Various ToSRGB calls (different code paths)
      auto full = img.ToSRGB();
      if (w >= 16 && h >= 16) {
        auto partial = img.ToSRGB(0, 0, w/2, h/2);
      }
      
      // Component operations
      for (int c = 0; c < 3; ++c) {
        auto& comp = img.component(c);
        if (comp.width_in_blocks() > 0 && comp.height_in_blocks() > 0) {
          guetzli::coeff_t block[64];
          comp.GetCoeffBlock(0, 0, block);
          comp.SetCoeffBlock(0, 0, block);
        }
      }
    }
    
    // Write JPEG
    std::string output;
    guetzli::JPEGOutput out([](void* d, const uint8_t* b, size_t c) -> int {
      static_cast<std::string*>(d)->append((const char*)b, c);
      return c;
    }, &output);
    guetzli::WriteJpeg(jpg, false, out);
    
    return 0;
  }
  
  // ==================== MODE 128-191: Preprocessing + Downsample ====================
  // Hits: preprocess_downsample.cc with all its complex functions
  if (mode < 192) {
    if (size < 20) return 0;
    
    int w = 16 + ((data[1] % 8) * 8);
    int h = 16 + ((data[2] % 8) * 8);
    if (w * h > 4000) { w = h = 32; }
    
    std::vector<uint8_t> rgb(w * h * 3);
    for (size_t i = 0; i < rgb.size(); ++i) {
      rgb[i] = data[3 + (i % (size - 3))];
    }
    
    // RGBToYUV420 (complex iterative solver)
    auto yuv420 = guetzli::RGBToYUV420(rgb, w, h);
    
    if (!yuv420.empty() && yuv420.size() >= 3) {
      uint8_t params = data[size - 1];
      float sigma = 0.5f + ((params & 0x07) * 0.2f);
      float amount = 0.1f + (((params >> 3) & 0x07) * 0.1f);
      bool blur = (params & 0x40) != 0;
      bool sharpen = (params & 0x80) != 0;
      
      // PreProcessChannel on V (red areas)
      auto processed_v = guetzli::PreProcessChannel(
          w, h, 2, sigma, amount, blur, sharpen, yuv420);
      
      // PreProcessChannel on U (blue areas)
      auto processed_u = guetzli::PreProcessChannel(
          w, h, 1, 1.0f, 0.5f, !blur, !sharpen, processed_v);
    }
    
    return 0;
  }
  
  // ==================== MODE 192-223: JPEG Reader Edge Cases ====================
  // Hits: jpeg_data_reader.cc error branches
  if (mode < 224) {
    std::string jpeg_str(reinterpret_cast<const char*>(data + 1), size - 1);
    guetzli::JPEGData jpg;
    
    // Try all read modes
    guetzli::ReadJpeg(jpeg_str, guetzli::JPEG_READ_HEADER, &jpg);
    guetzli::ReadJpeg(jpeg_str, guetzli::JPEG_READ_TABLES, &jpg);
    guetzli::ReadJpeg(jpeg_str, guetzli::JPEG_READ_ALL, &jpg);
    
    if (jpg.width > 0 && jpg.height > 0 && 
        jpg.width < 100 && jpg.height < 100) {
      std::string output;
      guetzli::JPEGOutput out([](void* d, const uint8_t* b, size_t c) -> int {
        static_cast<std::string*>(d)->append((const char*)b, c);
        return c;
      }, &output);
      
      guetzli::WriteJpeg(jpg, false, out);
      output.clear();
      guetzli::WriteJpeg(jpg, true, out);  // With metadata clearing
    }
    
    return 0;
  }
  
  // ==================== MODE 224-255: Varied Quantization ====================
  // Hits: entropy_encode.cc branches (different Huffman trees)
  {
    if (size < 200) return 0;
    
    int w = 24;
    int h = 24;
    
    std::vector<uint8_t> rgb(w * h * 3);
    for (size_t i = 0; i < rgb.size(); ++i) {
      rgb[i] = data[i % (size / 2)];
    }
    
    int quant[192];
    for (int i = 0; i < 192; ++i) {
      uint8_t val = data[(size / 2) + (i % (size / 2))];
      
      if (mode < 232) {
        quant[i] = 1 + (val % 5);        // High quality
      } else if (mode < 240) {
        quant[i] = 20 + (val % 80);      // Low quality
      } else if (mode < 248) {
        quant[i] = (i % 2) ? (1 + val % 10) : (30 + val % 50);  // Mixed
      } else {
        quant[i] = 1 + (val % 255);      // Extreme variation
      }
    }
    
    guetzli::JPEGData jpg;
    if (guetzli::EncodeRGBToJpeg(rgb, w, h, quant, &jpg)) {
      std::string output;
      guetzli::JPEGOutput out([](void* d, const uint8_t* b, size_t c) -> int {
        static_cast<std::string*>(d)->append((const char*)b, c);
        return c;
      }, &output);
      guetzli::WriteJpeg(jpg, false, out);
    }
  }

  return 0;
}