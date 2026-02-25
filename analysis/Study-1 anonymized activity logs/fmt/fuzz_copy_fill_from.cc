// fuzz_copy_fill_from.cc
#include <cstdint>
#include <cstddef>
#include <string>
#include <iterator>

#include <fmt/format.h>  // pulls in fmt::format_specs in v12

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size < 2) return 0;

  // lengths in [0,4], as fmt stores up to 4 bytes for fill
  size_t p = 0;
  const size_t len1 = data[p++] % 5;
  const size_t len2 = data[p++] % 5;

  auto take = [&](size_t want) -> std::string {
    size_t remain = size > p ? (size - p) : 0;
    size_t take_n = want <= remain ? want : remain;
    std::string s(reinterpret_cast<const char*>(data + p), take_n);
    p += take_n;
    return s;
  };

  std::string fill1 = take(len1);
  std::string fill2 = take(len2);

  unsigned width1 = (size > p) ? (1u + data[p++] % 64u) : 8u;
  unsigned width2 = (size > p) ? (1u + data[p++] % 64u) : 12u;

  // format_specs lives in fmt (v12 inline ns). No need to name v12 explicitly.
  fmt::format_specs src;
  fmt::format_specs dst;

  src.width = static_cast<int>(width1);
  dst.width = static_cast<int>(width2);

  // Populate src fill (0..4 bytes)
  if (fill1.empty()) {
    src.set_fill('*');
  } else if (fill1.size() == 1) {
    src.set_fill(fill1[0]);
  } else {
    src.set_fill(fmt::basic_string_view<char>(fill1.data(), fill1.size()));
  }

  // Pre-seed dst with something different, then copy from src.
  if (fill2.empty()) {
    dst.set_fill('#');
  } else if (fill2.size() == 1) {
    dst.set_fill(fill2[0]);
  } else {
    dst.set_fill(fmt::basic_string_view<char>(fill2.data(), fill2.size()));
  }

  // API under test:
  dst.copy_fill_from(src);

  // Repeat a couple of times to exercise overwrite/size transitions
  dst.copy_fill_from(src);
  if (!fill2.empty()) {
    // change src fill size (toggle between 1 and multi) then copy again
    if (fill2.size() == 1) {
      std::string two = fill2 + fill2; // 2-byte multi-unit
      src.set_fill(fmt::basic_string_view<char>(two.data(), two.size()));
    } else {
      src.set_fill(fill2[0]); // collapse to single-unit
    }
    dst.copy_fill_from(src);
  }

  // No assertions/IO: sanitizer findings == bug
  return 0;
}

