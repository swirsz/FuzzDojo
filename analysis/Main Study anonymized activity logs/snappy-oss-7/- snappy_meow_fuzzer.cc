
#include <stdint.h>

#include <cassert>
#include <string>

#include "snappy-sinksource.h"
#include "snappy-stubs-internal.h"
#include "snappy.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
/*
  // Avaulable functions

  size_t CompressFromIOVec(const struct iovec* iov, size_t iov_cnt, std::string* compressed);
  bool RawUncompressToIOVec(const char* compressed, size_t compressed_length, const struct iovec* iov, size_t iov_cnt);

  size_t Compress(Source* reader, Sink* writer);
*/



    std::string input(reinterpret_cast<const char*>(data), size);
    std::string compressed;
    snappy::Compress(input.data(), input.size(), &compressed);


    // snappy::ByteArraySource reader(input.data(), input.size());
    // std::string compressed2;
    // snappy::UncheckedByteArraySink writer(snappy::string_as_array(&compressed2));
    // snappy::Compress(&reader, &writer);

    snappy::ByteArraySource compressed_reader(compressed.data(), compressed.size());
    snappy::IsValidCompressed(&compressed_reader);

    uint32_t uncompressed_size;
    // bool is_size_passed =
    snappy::ByteArraySource compressed_reader2(compressed.data(), compressed.size());
    snappy::GetUncompressedLength(&compressed_reader2, &uncompressed_size);

  // uncompress using source and sink
  std::string uncomp_str;
  uncomp_str.resize(input.size());
  snappy::ByteArraySource source(compressed.data(), compressed.size());
  snappy::UncheckedByteArraySink sink(snappy::string_as_array(&uncomp_str));
  snappy::Uncompress(&source, &sink);
  snappy::UncompressAsMuchAsPossible(&source, &sink);

  // Uncompress into iovec
    static const int kNumBlocks = 10;
    struct iovec vec[kNumBlocks];
    const int block_size = 1 + input.size() / kNumBlocks;
    std::string iovec_data(block_size * kNumBlocks, 'x');
    for (int i = 0; i < kNumBlocks; ++i) {
      vec[i].iov_base = snappy::string_as_array(&iovec_data) + i * block_size;
      vec[i].iov_len = block_size;
    }
    snappy::RawUncompressToIOVec(compressed.data(), compressed.size(), vec, kNumBlocks);

/*
  // Uncompress into an iovec containing ten entries.
  const int kNumEntries = 10;
  struct iovec iov[kNumEntries];
  char* dst = new char[input.size()];
  size_t used_so_far = 0;
  for (int i = 0; i < kNumEntries; ++i) {
    iov[i].iov_base = dst + used_so_far;
    if (used_so_far == input.size()) {
      iov[i].iov_len = 0;
      continue;
    }

    if (i == kNumEntries - 1) {
      iov[i].iov_len = input.size() - used_so_far;
    } else {
      iov[i].iov_len = input.size() / kNumEntries;
    }
    used_so_far += iov[i].iov_len;
  }


    // const struct iovec* iov;
    // size_t iov_cnt;
    snappy::RawUncompressToIOVec(compressed.data(), compressed.size(), iov, kNumEntries);
    snappy::CompressFromIOVec(iov, kNumEntries, &compressed);
*/
/*

  SnappyDecompressionValidator writer;


    std::string uncompressed_after_compress;
    bool uncompress_succeeded = snappy::Uncompress(
        compressed.data(), compressed.size(), &uncompressed_after_compress);

    (void)uncompress_succeeded;  // Variable only used in debug builds.
    assert(uncompress_succeeded);
    assert(input == uncompressed_after_compress);

  // Avoid self-crafted decompression bombs.
  size_t uncompressed_size;
  constexpr size_t kMaxUncompressedSize = 1 << 20;
  bool get_uncompressed_length_succeeded = snappy::GetUncompressedLength(
      input.data(), input.size(), &uncompressed_size);
  if (!get_uncompressed_length_succeeded ||
      (uncompressed_size > kMaxUncompressedSize)) {
    return 0;
  }

  std::string uncompressed;
  // The return value of snappy::Uncompress() is ignored because decompression
  // will fail on invalid inputs.
  snappy::Uncompress(input.data(), input.size(), &uncompressed);

*/

  return 0;
}
