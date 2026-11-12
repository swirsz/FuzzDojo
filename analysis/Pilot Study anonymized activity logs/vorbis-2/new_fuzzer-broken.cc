#include <stdio.h>
#include <string.h>
#include <cstdint>
// #include <vorbis/vorbisfile.h>
// #include <vorbis/vorbis.h>
#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>
#include <fuzzer/FuzzedDataProvider.h>

struct vorbis_data {
  const uint8_t *current;
  const uint8_t *data;
  size_t size;
};

// size_t read_func(void *ptr, size_t size1, size_t size2, void *datasource) {
//   vorbis_data* vd = (vorbis_data *)(datasource);
//   size_t len = size1 * size2;
//   if (vd->current + len > vd->data + vd->size) {
//       len = vd->data + vd->size - vd->current;
//   }
//   memcpy(ptr, vd->current, len);
//   vd->current += len;
//   return len;
// }

// int vorbis_encode_init_vbr(vorbis_info *vi, long channels, long rate, float base_quality);
// int vorbis_analysis_init(vorbis_dsp_state *v, vorbis_info *vi);
// void vorbis_info_init(vorbis_info *vi);
// void vorbis_info_clear(vorbis_info *vi);
// int vorbis_block_init(vorbis_dsp_state *v, vorbis_block *vb);
// void vorbis_dsp_clear(vorbis_dsp_state *v);
// int vorbis_analysis_wrote(vorbis_dsp_state *v, int vals);
// int vorbis_block_clear(vorbis_block *vb);
// float **vorbis_analysis_buffer(vorbis_dsp_state *v, int vals);
// int vorbis_analysis_blockout(vorbis_dsp_state *v, vorbis_block *vb);
// int vorbis_bitrate_addblock(vorbis_block *vb);


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!Data || Size < 4) return 0; // need a few bytes for params

  // Derive encoder params from the start of Data
  int channels = 1 + (Data[0] & 1);           // 1 or 2
  long rate    = 8000 + (Data[1] & 7) * 8000; // 8k,16k,...,64k
  float q;
  {
    // map byte to a reasonable VBR quality range [-0.1 .. 1.0]
    int v = (int)Data[2];
    q = -0.1f + (v / 255.0f) * 1.1f;
  }

  vorbis_info vi;
  vorbis_info_init(&vi);

  if (vorbis_encode_init_vbr(&vi, channels, rate, q)) {
    vorbis_info_clear(&vi);
    return 0;
  }

  vorbis_dsp_state vd;
  if (vorbis_analysis_init(&vd, &vi)) {
    vorbis_info_clear(&vi);
    return 0;
  }

  vorbis_block vb;
  if (vorbis_block_init(&vd, &vb)) {
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Use remaining data as interleaved 16-bit PCM. Ensure we don't request zero frames.
  const uint8_t *payload = Data + 3;
  size_t payload_size = (Size > 3) ? (Size - 3) : 0;
  if (payload_size < 2 * (size_t)channels) {
    // Not enough data for even one frame; still call wrote(0) and cleanup.
    vorbis_analysis_wrote(&vd, 0);
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Compute frames (limit to a sane max per call)
  size_t sample_bytes_per_frame = 2 * (size_t)channels; // int16 per channel
  size_t max_frames = payload_size / sample_bytes_per_frame;
  const int FRAMES_CAP = 4096;
  int frames = (int)(max_frames < FRAMES_CAP ? max_frames : FRAMES_CAP);
  if (frames <= 0) frames = 1;

  // Get buffer from libvorbis
  float **buffer = vorbis_analysis_buffer(&vd, frames);
  if (!buffer) {
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Fill buffer: map 2 bytes -> int16 -> float in [-1,1)
  size_t pos = 0;
  for (int i = 0; i < frames; ++i) {
    for (int ch = 0; ch < channels; ++ch) {
      // If we run out of payload, wrap around to reuse data (keeps harness robust)
      if (pos + 1 >= payload_size) pos = 0;
      uint16_t lo = payload[pos];
      uint16_t hi = payload[pos + 1];
      uint16_t u = (uint16_t)((hi << 8) | lo);
      int16_t s = (int16_t)u;
      buffer[ch][i] = (float)s / 32768.0f;
      pos += 2;
    }
  }

  // Announce the frames to the encoder
  vorbis_analysis_wrote(&vd, frames);

  // Pull analysis blocks and hand them into the bitrate pipeline.
  // This is the flow that will exercise mapping/bitrate-related functions.
  while (vorbis_analysis_blockout(&vd, &vb) == 1) {
    // Add this block to the bitrate layer; mapping functions can be called
    // during the subsequent packing/buffering steps inside libvorbis.
    vorbis_bitrate_addblock(&vb);

    // We won't produce ogg packets here - we just want the internal pipeline executed.
    // Optionally, to push further, you could call vorbis_bitrate_flushpacket and process packets.
  }

  // Signal end-of-stream (safe no-op if not required)
  vorbis_analysis_wrote(&vd, 0);

  // Cleanup
  vorbis_block_clear(&vb);
  vorbis_dsp_clear(&vd);
  vorbis_info_clear(&vi);
  return 0;
}


// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
//   ov_callbacks memory_callbacks = {0};
//   FuzzedDataProvider fuzz(Data, Size);
//   memory_callbacks.read_func = read_func;
//   vorbis_data data_st;
//   data_st.size = Size;
//   data_st.current = Data;
//   data_st.data = Data;
//   OggVorbis_File vf;
//   int result = ov_open_callbacks(&data_st, &vf, NULL, 0, memory_callbacks);
//   if (result < 0) {
//     return 0;
//   }
//   // int current_section = 0;
//   // int eof = 0;
//   // char buf[4096];
//   ov_time_seek_lap(&vf, fuzz.ConsumeFloatingPoint<double>());
//   ov_time_seek_page_lap(&vf, fuzz.ConsumeFloatingPoint<double>());

//   ov_pcm_seek_lap(&vf, fuzz.ConsumeIntegral<int64_t>());
//   ov_raw_seek_lap(&vf, fuzz.ConsumeIntegral<int64_t>());
//   ov_pcm_seek_page_lap(&vf, fuzz.ConsumeIntegral<int64_t>());

//   ov_halfrate(&vf, fuzz.ConsumeIntegralInRange<int>(0, 1));
//   // while (!eof) {
//   //   // read_result = ov_read(&vf, buf, sizeof(buf), 0, 2, 1, &current_section);
//   //   if (read_result != OV_HOLE && read_result <= 0) {
//   //     eof = 1;
//   //   }
//   // }
//   ov_clear(&vf);
//   return 0;
// }
