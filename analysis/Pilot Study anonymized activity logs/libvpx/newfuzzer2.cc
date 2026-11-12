/*
 * Fuzzer for libvpx VP9 decoder control: ctrl_set_reference
 *
 * Targets the decoder control map entry:
 *   { VP8_SET_REFERENCE, ctrl_set_reference }
 *
 * References:
 * - ctrl_set_reference implementation (image2yuvconfig + vp9_set_reference_dec)
 *   https://chromium.googlesource.com/webm/libvpx/+/master/vp9/vp9_dx_iface.c
 *
 * Build: gets compiled by OSS-Fuzz with libFuzzer and libvpx decoder.
 */

#include <cstdint>
#include <cstddef>
#include <algorithm>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"      // vpx_codec_iface_t for decoders (VP9)
#include "vpx/vp8.h"        // vpx_ref_frame_t, VP8_* reference enums
#include "vpx/vpx_image.h"  // vpx_img_alloc/free
}

static inline uint32_t ReadLE32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create decoder context
  vpx_codec_ctx_t dec;
  if (vpx_codec_dec_init(&dec, vpx_codec_vp9_dx(), /*cfg=*/nullptr, /*flags=*/0) != VPX_CODEC_OK) {
    return 0;
  }

  // Split the input:
  // - First slice initializes the decoder (must be non-empty so init path runs).
  // - Remainder populates a reference image we set via VP8_SET_REFERENCE.
  const size_t init_bytes = std::min<size_t>(size, 64);
  const uint8_t *init_data = data;
  const size_t init_size = init_bytes ? init_bytes : 1; // ensure non-zero
  uint8_t dummy = 0;
  if (init_bytes == 0) init_data = &dummy;

  // Feed some bytes so the decoder calls init_decoder() and creates ctx->pbi
  // (decoder_decode() initializes when pbi==NULL and data != NULL). :contentReference[oaicite:1]{index=1}
  (void)vpx_codec_decode(&dec, init_data, static_cast<unsigned int>(init_size), /*user_priv=*/nullptr, /*deadline=*/0);

  // Try to query frame size; if not available, derive bounded dims from fuzzer input.
  int frame_size_q[2] = {0, 0};
  if (vpx_codec_control(&dec, VP9D_GET_FRAME_SIZE, frame_size_q) != VPX_CODEC_OK ||
      frame_size_q[0] <= 0 || frame_size_q[1] <= 0) {
    // Make a small, safe canvas to avoid huge allocations.
    // Use a few bytes of the remaining input to pick dimensions.
    const uint8_t *p = data + init_bytes;
    size_t rem = (size > init_bytes) ? (size - init_bytes) : 0;

    uint32_t w = 16, h = 16;
    if (rem >= 8) {
      w = 1 + (ReadLE32(p) % 64);      // 1..64
      h = 1 + (ReadLE32(p + 4) % 64);  // 1..64
    }
    frame_size_q[0] = static_cast<int>(w);
    frame_size_q[1] = static_cast<int>(h);
  }

  // Allocate an I420 image for the reference frame.
  const int width = std::max(1, std::min(frame_size_q[0], 256));
  const int height = std::max(1, std::min(frame_size_q[1], 256));
  vpx_image_t img;
  if (!vpx_img_alloc(&img, VPX_IMG_FMT_I420, width, height, /*align=*/32)) {
    vpx_codec_destroy(&dec);
    return 0;
  }

  // Fill image planes with whatever remains from the fuzzer input (repeat if short).
  const uint8_t *payload = data + init_bytes;
  size_t payload_len = (size > init_bytes) ? (size - init_bytes) : 0;
  auto fill_plane = [&](uint8_t *dst, int stride, int w, int h) {
    size_t need = static_cast<size_t>(stride) * static_cast<size_t>(h);
    size_t off = 0;
    while (off < need) {
      if (payload_len == 0) {
        // deterministic filler when out of bytes
        dst[off++] = static_cast<uint8_t>((off * 131u) ^ 0x5A);
      } else {
        size_t chunk = std::min(need - off, payload_len);
        std::memcpy(dst + off, payload, chunk);
        off += chunk;
        // Move window forward but keep at least some variability across planes
        size_t advance = std::min(chunk, payload_len);
        payload += advance;
        payload_len -= advance;
      }
    }
  };
  // Y plane
  fill_plane(img.planes[0], img.stride[0], img.d_w, img.d_h);
  // U/V planes (I420 -> half resolution)
  fill_plane(img.planes[1], img.stride[1], (img.d_w + 1) / 2, (img.d_h + 1) / 2);
  fill_plane(img.planes[2], img.stride[2], (img.d_w + 1) / 2, (img.d_h + 1) / 2);

  // Choose a reference slot.
  // vpx_ref_frame_type_t is VP8_{LAST,GOLD,ALTR}_FRAME with values {1,2,4}. :contentReference[oaicite:2]{index=2}
  vpx_ref_frame_t ref{};
  const uint8_t tag = (size > 0) ? data[size - 1] : 0;
  switch (tag % 3) {
    case 0: ref.frame_type = VP8_LAST_FRAME; break;
    case 1: ref.frame_type = VP8_GOLD_FRAME; break;
    default: ref.frame_type = VP8_ALTR_FRAME; break;
  }
  ref.img = img;

  // Invoke the control that maps to ctrl_set_reference:
  //   image2yuvconfig(&frame->img, &sd);
  //   return vp9_set_reference_dec(&ctx->pbi->common, ref_frame_to_vp9_reframe(...), &sd);
  // This requires ctx->pbi to be non-null, hence the earlier decode call. :contentReference[oaicite:3]{index=3}
  (void)vpx_codec_control(&dec, VP8_SET_REFERENCE, &ref);

  vpx_img_free(&img);
  vpx_codec_destroy(&dec);
  return 0;
}

