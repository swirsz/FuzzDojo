#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <algorithm>

#include "snappy.h"
#include "snappy-sinksource.h"

#ifdef __has_include
#  if __has_include(<fuzzer/FuzzedDataProvider.h>)
#    include <fuzzer/FuzzedDataProvider.h>
#    define HAS_LIBFUZZER_PROVIDER 1
#  elif __has_include("FuzzedDataProvider.h")
#    include "FuzzedDataProvider.h"
#    define HAS_LIBFUZZER_PROVIDER 1
#  endif
#endif

#ifndef HAS_LIBFUZZER_PROVIDER
class FuzzedDataProvider {
 public:
  FuzzedDataProvider(const uint8_t* data, size_t size)
      : data_(data), size_(size), offset_(0) {}
  template <typename T>
  T ConsumeIntegralInRange(T min, T max) {
    if (min > max) std::swap(min, max);
    if (offset_ + sizeof(T) > size_) return min;
    T v = 0;
    memcpy(&v, data_ + offset_, sizeof(T));
    offset_ += sizeof(T);
    if (max == min) return min;
    return static_cast<T>(min + (v % (static_cast<uint64_t>(max - min) + 1)));
  }
  std::string ConsumeRandomLengthString(size_t max_len) {
    size_t n = ConsumeIntegralInRange<size_t>(0, std::min(max_len, RemainingBytes()));
    std::string s(reinterpret_cast<const char*>(data_ + offset_), n);
    offset_ += n;
    return s;
  }
  std::vector<uint8_t> ConsumeBytes(size_t n) {
    n = std::min(n, RemainingBytes());
    std::vector<uint8_t> out(data_ + offset_, data_ + offset_ + n);
    offset_ += n;
    return out;
  }
  size_t RemainingBytes() const { return size_ - offset_; }
 private:
  const uint8_t* data_;
  size_t size_;
  size_t offset_;
};
#endif

// Helper: build a vector of iov-like slices from a buffer, including zero-lengths.
static std::vector<std::string> MakeFragments(FuzzedDataProvider& fdp,
                                             const uint8_t* buf, size_t len,
                                             size_t max_pieces) {
  std::vector<std::string> frags;
  if (len == 0 || max_pieces == 0) return frags;
  size_t pieces = std::min<size_t>(max_pieces, std::max<size_t>(1, fdp.ConsumeIntegralInRange<size_t>(1, max_pieces)));
  size_t off = 0;
  while (off < len && frags.size() < pieces) {
    size_t remain = len - off;
    size_t take = std::min<size_t>(remain, fdp.ConsumeIntegralInRange<size_t>(0, remain));
    frags.emplace_back(reinterpret_cast<const char*>(buf + off), take);
    off += take;
  }
  // Occasionally insert explicit zero-length fragments to exercise edge cases.
  size_t zero_count = fdp.ConsumeIntegralInRange<size_t>(0, 2);
  for (size_t i = 0; i < zero_count; ++i) frags.emplace_back("");
  if (off < len) frags.emplace_back(reinterpret_cast<const char*>(buf + off), len - off);
  return frags;
}

// Oracle: strict equality of round-trip results
static void ExpectEqual(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) {
    assert(false && "size mismatch after round-trip");
  }
  if (a != b) {
    assert(false && "content mismatch after round-trip");
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Hard cap to avoid pathological allocations in fuzzer infra.
  if (size > (1 << 20)) return 0;  // 1 MiB cap for inputs

  FuzzedDataProvider fdp(data, size);

  // Split header for mode and knobs to drive more branches.
  const uint8_t mode = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);  // 6 modes
  const bool skew_small_buffers = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);
  const bool try_corrupt = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);

  // Remaining bytes are the payload.
  std::vector<uint8_t> payload = fdp.ConsumeBytes(fdp.RemainingBytes());
  const char* in_ptr = reinterpret_cast<const char*>(payload.data());
  const size_t in_len = payload.size();

  // Common buffers
  std::string compressed, decompressed;
  size_t max_comp = snappy::MaxCompressedLength(in_len);
  compressed.resize(max_comp);

  // MODE 0: RawCompress + RawUncompress (direct)
  if (mode == 0) {
    size_t produced = 0;
    if (in_len) {
      snappy::RawCompress(in_ptr, in_len, &compressed[0], &produced);
    } else {
      // Zero-length inputs should still be valid round-trips.
      produced = 0;
    }
    compressed.resize(produced);

    size_t ulen = 0;
    bool got_len = snappy::GetUncompressedLength(compressed.data(), compressed.size(), &ulen);
    if (produced == 0) {
      // Empty input should decode to empty successfully.
      assert(got_len && ulen == 0);
    }

    decompressed.resize(ulen);
    bool ok = (ulen == 0) ? true : snappy::RawUncompress(compressed.data(), compressed.size(), &decompressed[0]);
    if (ulen == 0) decompressed.clear();
    assert(ok || compressed.empty());
    if (ok) ExpectEqual(std::string(in_ptr, in_len), decompressed);
  }

  // MODE 1: Stream-style Source/Sink using *tracked* produced size
  if (mode == 1) {
    snappy::ByteArraySource source(in_ptr, in_len);
    // Pre-allocate and compress; then shrink to actual size written using produced length.
    size_t produced = 0;
    if (in_len) snappy::RawCompress(in_ptr, in_len, &compressed[0], &produced);
    compressed.resize(produced);

    // Feed only the produced bytes to the next stage
    snappy::ByteArraySource csrc(compressed.data(), compressed.size());

    size_t ulen = 0;
    bool have = snappy::GetUncompressedLength(compressed.data(), compressed.size(), &ulen);
    if (have && ulen <= (1u << 24)) {  // 16 MiB cap
      decompressed.resize(ulen);
      bool ok = snappy::RawUncompress(compressed.data(), compressed.size(), &decompressed[0]);
      if (ok) ExpectEqual(std::string(in_ptr, in_len), decompressed);
    } else {
      // If length is absurd or can't be read, Uncompress should fail.
      bool ok = snappy::Uncompress(&csrc, &decompressed);
      (void)ok;  // no assert here; just execute the path
    }
  }

  // MODE 2: IOVec-style fragmentation for CompressFromIOVec/RawUncompressToIOVec surrogate
  if (mode == 2) {
    auto frags = MakeFragments(fdp, payload.data(), payload.size(), /*max_pieces=*/16);

    // Concatenate frags for RawCompress (upstream Snappy does not expose IOVec compress everywhere)
    std::string joined;
    for (const auto& s : frags) joined.append(s);

    size_t produced = 0;
    if (!joined.empty()) snappy::RawCompress(joined.data(), joined.size(), &compressed[0], &produced);
    compressed.resize(produced);

    // Decompress to a set of output fragments with varied sizing (including skewed small buffers)
    size_t ulen = 0;
    bool have = snappy::GetUncompressedLength(compressed.data(), compressed.size(), &ulen);
    if (have && ulen <= (1u << 24)) {
      // Create piecewise targets totalling ulen
      std::vector<std::pair<char*, size_t>> outs;
      std::vector<std::string> out_vec;
      size_t remaining = ulen;
      while (remaining > 0) {
        size_t piece = std::min<size_t>(remaining, skew_small_buffers ? 1 + (remaining % 7) : 1 + (remaining % 4096));
        out_vec.emplace_back(piece, '\0');
        remaining -= piece;
      }
      for (auto& s : out_vec) outs.emplace_back(&s[0], s.size());

      // Fallback since upstream does not provide RawUncompressToIOVec: decompress to contiguous, then scatter.
      std::string flat;
      flat.resize(ulen);
      bool ok = snappy::RawUncompress(compressed.data(), compressed.size(), &flat[0]);
      if (ok) {
        size_t off = 0;
        for (auto& p : outs) {
          memcpy(p.first, flat.data() + off, p.second);
          off += p.second;
        }
        // Re-join and compare to original
        std::string rejoined;
        for (auto& s : out_vec) rejoined.append(s);
        ExpectEqual(joined, rejoined);
      }
    }
  }

  // MODE 3: Validate / IsValidCompressedBuffer and consistency with (Un)Compress
  if (mode == 3) {
    size_t produced = 0;
    if (in_len) snappy::RawCompress(in_ptr, in_len, &compressed[0], &produced);
    compressed.resize(produced);

    const bool valid = snappy::IsValidCompressedBuffer(compressed.data(), compressed.size());
    size_t ulen = 0;
    const bool have_len = snappy::GetUncompressedLength(compressed.data(), compressed.size(), &ulen);

    if (valid && have_len) {
      decompressed.resize(ulen);
      bool ok = snappy::RawUncompress(compressed.data(), compressed.size(), &decompressed[0]);
      assert(ok);
      ExpectEqual(std::string(in_ptr, in_len), decompressed);
    } else {
      // If deemed invalid or length unknown, decompression should fail or produce empty.
      bool ok = snappy::RawUncompress(compressed.data(), compressed.size(), nullptr);
      (void)ok;  // upstream RawUncompress(nullptr) may not be allowed; path executed for coverage
    }
  }

  // MODE 4: Truncation / corruption negative tests
  if (mode == 4) {
    size_t produced = 0;
    if (in_len) snappy::RawCompress(in_ptr, in_len, &compressed[0], &produced);
    compressed.resize(produced);

    if (!compressed.empty()) {
      // Random truncation
      size_t cut = fdp.ConsumeIntegralInRange<size_t>(0, compressed.size());
      std::string trunc = compressed.substr(0, cut);
      size_t ulen = 0;
      bool have_len = snappy::GetUncompressedLength(trunc.data(), trunc.size(), &ulen);
      if (have_len && ulen <= (1u << 24)) {
        decompressed.resize(ulen);
        bool ok = snappy::RawUncompress(trunc.data(), trunc.size(), &decompressed[0]);
        // Truncation should often fail; allow success for corner cases but still exercise path.
        (void)ok;
      }

      // Byte corruption
      std::string corrupt = compressed;
      size_t flips = std::min<size_t>(fdp.ConsumeIntegralInRange<size_t>(1, 8), corrupt.size());
      for (size_t i = 0; i < flips; ++i) {
        size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, corrupt.size() - 1);
        corrupt[idx] ^= static_cast<char>(1u << (i % 8));
      }
      bool valid = snappy::IsValidCompressedBuffer(corrupt.data(), corrupt.size());
      size_t ulen2 = 0;
      bool have2 = snappy::GetUncompressedLength(corrupt.data(), corrupt.size(), &ulen2);
      if (valid && have2 && ulen2 <= (1u << 24)) {
        decompressed.resize(ulen2);
        bool ok = snappy::RawUncompress(corrupt.data(), corrupt.size(), &decompressed[0]);
        (void)ok;  // may succeed in rare cases; we care about traversing error-handling
      }
    }
  }

  // MODE 5: Small-buffer skew testing (buffers slightly too small or large)
  if (mode == 5) {
    // Compress
    size_t produced = 0;
    if (in_len) snappy::RawCompress(in_ptr, in_len, &compressed[0], &produced);
    compressed.resize(produced);

    // Intentionally allocate a buffer that could be slightly off
    size_t ulen = 0;
    bool have = snappy::GetUncompressedLength(compressed.data(), compressed.size(), &ulen);
    if (have) {
      size_t skew = fdp.ConsumeIntegralInRange<size_t>(0, 3);  // 0: exact, 1: -1 (clamped), 2: +1, 3: +page-ish
      size_t target = ulen;
      if (skew == 1 && ulen > 0) target = ulen - 1;
      if (skew == 2) target = ulen + 1;
      if (skew == 3) target = ulen + 4096;
      decompressed.assign(target, '\0');
      bool ok = (target >= ulen) ? snappy::RawUncompress(compressed.data(), compressed.size(), &decompressed[0])
                                 : false;  // too small: skip unsafe call
      if (ok) {
        decompressed.resize(ulen);
        ExpectEqual(std::string(in_ptr, in_len), decompressed);
      }
    }
  }

  (void)skew_small_buffers;
  (void)try_corrupt;
  return 0;
}
