#include <stdio.h>
#include <string.h>
#include <cstdint>
#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>
#include <fuzzer/FuzzedDataProvider.h>

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

  if (vorbis_encode_init_vbr(&vi, channels, rate, q) != 0) {
    vorbis_info_clear(&vi);
    return 0;
  }

  vorbis_dsp_state vd;
  if (vorbis_analysis_init(&vd, &vi) != 0) {
    vorbis_info_clear(&vi);
    return 0;
  }

  vorbis_block vb;
  if (vorbis_block_init(&vd, &vb) != 0) {
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Use remaining data as interleaved 16-bit PCM
  const uint8_t *payload = Data + 3;
  size_t payload_size = (Size > 3) ? (Size - 3) : 0;
  
  size_t sample_bytes_per_frame = 2 * (size_t)channels; // int16 per channel
  
  if (payload_size < sample_bytes_per_frame) {
    // Not enough data for even one frame; signal end and cleanup
    vorbis_analysis_wrote(&vd, 0);
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Compute frames (limit to a sane max per call)
  size_t max_frames = payload_size / sample_bytes_per_frame;
  const int FRAMES_CAP = 4096;
  int frames = (int)(max_frames < (size_t)FRAMES_CAP ? max_frames : FRAMES_CAP);
  
  if (frames <= 0) {
    // Should not happen due to check above, but be defensive
    vorbis_analysis_wrote(&vd, 0);
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Get buffer from libvorbis
  float **buffer = vorbis_analysis_buffer(&vd, frames);
  if (!buffer) {
    vorbis_analysis_wrote(&vd, 0);
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Fill buffer: map 2 bytes -> int16 -> float in [-1,1)
  size_t pos = 0;
  for (int i = 0; i < frames; ++i) {
    for (int ch = 0; ch < channels; ++ch) {
      // Check if we have enough bytes remaining
      if (pos + 2 > payload_size) {
        // Wraparound to reuse data (keeps harness robust)
        pos = 0;
      }
      
      uint16_t lo = payload[pos];
      uint16_t hi = payload[pos + 1];
      uint16_t u = (uint16_t)((hi << 8) | lo);
      int16_t s = (int16_t)u;
      buffer[ch][i] = (float)s / 32768.0f;
      pos += 2;
    }
  }

  // Announce the frames to the encoder
  if (vorbis_analysis_wrote(&vd, frames) != 0) {
    // Error writing; cleanup and exit
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
    vorbis_info_clear(&vi);
    return 0;
  }

  // Pull analysis blocks and hand them into the bitrate pipeline
  int blockout_result;
  while ((blockout_result = vorbis_analysis_blockout(&vd, &vb)) == 1) {
    // Add this block to the bitrate layer
    int bitrate_result = vorbis_bitrate_addblock(&vb);
    (void)bitrate_result; // Suppress unused warning; we continue regardless
    
    // Optionally retrieve packets to exercise more code:
    // ogg_packet op;
    // while (vorbis_bitrate_flushpacket(&vd, &op)) {
    //   // Process packet...
    // }
  }

  // Signal end-of-stream
  vorbis_analysis_wrote(&vd, 0);
  
  // Final blockout to flush any remaining data
  while (vorbis_analysis_blockout(&vd, &vb) == 1) {
    vorbis_bitrate_addblock(&vb);
  }

  // Cleanup
  vorbis_block_clear(&vb);
  vorbis_dsp_clear(&vd);
  vorbis_info_clear(&vi);
  return 0;
}