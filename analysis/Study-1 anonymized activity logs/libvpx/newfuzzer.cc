#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"     // VP9 decoder iface + VP9D_* controls
#include "vpx/vpx_image.h"
}

// ---------------- IVF helpers (VP9 "VP90") ----------------

static bool IsIvfVp9(const uint8_t* data, size_t size) {
  // IVF header: 32 bytes. Magic "DKIF" at 0..3, fourcc "VP90" at 8..11.
  if (!data || size < 32) return false;
  if (!(data[0]=='D' && data[1]=='K' && data[2]=='I' && data[3]=='F')) return false;
  return (data[8]=='V' && data[9]=='P' && data[10]=='9' && data[11]=='0');
}

static bool ParseIvfFrame(const uint8_t* data, size_t size,
                          size_t* off, const uint8_t** frame_ptr, size_t* frame_sz) {
  if (*off + 12 > size) return false;
  uint32_t fs = (uint32_t)data[*off] |
                ((uint32_t)data[*off + 1] << 8) |
                ((uint32_t)data[*off + 2] << 16) |
                ((uint32_t)data[*off + 3] << 24);
  *off += 12;  // skip size (4) + pts (8)
  if (*off + fs > size) return false;
  *frame_ptr = data + *off;
  *frame_sz = fs;
  *off += fs;
  return true;
}

// ---------------- Fuzzer entry ----------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size == 0) return 0;

  // A few config bytes to vary behavior without heavy parsing.
  const uint8_t b0 = data[0];
  const uint8_t b1 = (size > 1) ? data[1] : 0;

  // Init VP9 decoder with >1 thread to actually engage row-MT.
  vpx_codec_ctx_t ctx;
  std::memset(&ctx, 0, sizeof(ctx));

  vpx_codec_dec_cfg_t cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.w = 0;
  cfg.h = 0;
  // 2..8 threads; keep bounded for stability.
  cfg.threads = 2 + (b0 & 0x7);  // 2..9 but lib may clamp internally

  if (vpx_codec_dec_init(&ctx, vpx_codec_vp9_dx(), &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // Enable row-based multi-threading; optionally enable loop-filter optimization.
  // These are public decoder controls; errors are ignored so fuzzing can continue.
  int on = 1;
  (void)vpx_codec_control(&ctx, VP9D_SET_ROW_MT, on);

  if (b1 & 0x1) {
    (void)vpx_codec_control(&ctx, VP9D_SET_LOOP_FILTER_OPT, on);
  }

  // Decode IVF multi-frame or treat input as a single compressed frame.
  if (IsIvfVp9(data, size)) {
    size_t off = 32;
    const uint8_t* frame_ptr = nullptr;
    size_t frame_sz = 0;

    int frames = 0;
    while (frames < 100 && ParseIvfFrame(data, size, &off, &frame_ptr, &frame_sz)) {
      (void)vpx_codec_decode(&ctx, frame_ptr, static_cast<unsigned int>(frame_sz), nullptr, 0);

      // Drain frames to run post-decode + LF paths and keep workers busy.
      vpx_codec_iter_t it = nullptr;
      vpx_image_t* img = nullptr;
      while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
        volatile int w = img->d_w;
        volatile int h = img->d_h;
        (void)w; (void)h;
      }
      frames++;
    }
  } else {
    (void)vpx_codec_decode(&ctx, data, static_cast<unsigned int>(size), nullptr, 0);
    vpx_codec_iter_t it = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
      volatile int w = img->d_w;
      volatile int h = img->d_h;
      (void)w; (void)h;
    }
  }

  // Final flush tick (covers a small branch in the plumbing).
  (void)vpx_codec_decode(&ctx, nullptr, 0, nullptr, 0);

  vpx_codec_destroy(&ctx);
  return 0;
}

