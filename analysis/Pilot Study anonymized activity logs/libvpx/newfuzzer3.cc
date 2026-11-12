#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"     // vpx_codec_vp8_dx, vp8_postproc_cfg_t, VP8_* flags
#include "vpx/vpx_image.h"
}

// ---------- Minimal IVF helpers (VP8 "VP80") ----------

static bool IsIvfVp8(const uint8_t* data, size_t size) {
  if (size < 32) return false;
  // "DKIF"
  if (!(data[0]=='D' && data[1]=='K' && data[2]=='I' && data[3]=='F')) return false;
  // fourcc "VP80"
  return (data[8]=='V' && data[9]=='P' && data[10]=='8' && data[11]=='0');
}

static bool ParseIvfFrame(const uint8_t* data, size_t size,
                          size_t* off, const uint8_t** frame_ptr, size_t* frame_sz) {
  if (*off + 12 > size) return false;
  uint32_t fs = (uint32_t)data[*off] |
                ((uint32_t)data[*off + 1] << 8) |
                ((uint32_t)data[*off + 2] << 16) |
                ((uint32_t)data[*off + 3] << 24);
  *off += 12;  // skip <size><pts>
  if (*off + fs > size) return false;
  *frame_ptr = data + *off;
  *frame_sz = fs;
  *off += fs;
  return true;
}

// ---------- Fuzzer entry ----------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size == 0) return 0;

  // Light config bytes
  const uint8_t b0 = data[0];
  const uint8_t b1 = (size > 1) ? data[1] : 0;
  const uint8_t b2 = (size > 2) ? data[2] : 0;

  // Init VP8 decoder
  vpx_codec_ctx_t ctx;
  std::memset(&ctx, 0, sizeof(ctx));

  vpx_codec_dec_cfg_t cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.w = 0; cfg.h = 0;
  cfg.threads = 1 + (b0 & 0x3); // 1..4 threads

  if (vpx_codec_dec_init(&ctx, vpx_codec_vp8_dx(), &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // ---- Enable postproc with MFQE (core requirement) ----
  vp8_postproc_cfg_t pp;
  std::memset(&pp, 0, sizeof(pp));
  // Always include MFQE; optionally combine with other features to hit more branches.
  pp.post_proc_flag = VP8_MFQE
                    | ((b0 & 0x10) ? VP8_DEBLOCK       : 0)
                    | ((b0 & 0x20) ? VP8_DEMACROBLOCK  : 0)
                    | ((b0 & 0x40) ? VP8_ADDNOISE      : 0);
  pp.deblocking_level = (b1 % 9); // 0..8
  pp.noise_level      = (b2 % 4); // 0..3
  (void)vpx_codec_control(&ctx, VP8_SET_POSTPROC, &pp);

  // Flip MFQE once mid-stream to tick reconfig paths.
  const bool flip_mfqe = (b2 & 0x80) != 0;

  auto drain_frames = [&]() {
    vpx_codec_iter_t it = nullptr;
    vpx_image_t* img = nullptr;
    while ((img = vpx_codec_get_frame(&ctx, &it)) != nullptr) {
      // Touch a few fields; MFQE operates on decoded output.
      volatile int w = img->d_w;
      volatile int h = img->d_h;
      (void)w; (void)h;
    }
  };

  if (IsIvfVp8(data, size)) {
    size_t off = 32;
    const uint8_t* frame_ptr = nullptr;
    size_t frame_sz = 0;

    int frames = 0;
    while (frames < 120 && ParseIvfFrame(data, size, &off, &frame_ptr, &frame_sz)) {
      (void)vpx_codec_decode(&ctx, frame_ptr, static_cast<unsigned int>(frame_sz), nullptr, 0);
      drain_frames();

      // Toggle MFQE flag after a few frames to exercise dynamic path changes.
      if (flip_mfqe && frames == 2) {
        vp8_postproc_cfg_t pp2 = pp;
        pp2.post_proc_flag ^= VP8_MFQE; // flip MFQE on/off
        (void)vpx_codec_control(&ctx, VP8_SET_POSTPROC, &pp2);
      }
      frames++;
    }
  } else {
    // Treat entire buffer as a single compressed frame (MFQE will be a no-op
    // until a subsequent frame arrives; still useful for control coverage).
    (void)vpx_codec_decode(&ctx, data, static_cast<unsigned int>(size), nullptr, 0);
    drain_frames();
  }

  // Final flush to cover plumbing branches.
  (void)vpx_codec_decode(&ctx, nullptr, 0, nullptr, 0);
  vpx_codec_destroy(&ctx);
  return 0;
}

