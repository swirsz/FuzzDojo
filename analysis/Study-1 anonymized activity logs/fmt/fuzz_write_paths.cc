// OSS-Fuzz target: drives integer/float/string writer paths via format_to.
// v12, C++14.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <limits>
#include <iterator>

#include <fmt/format.h>

static const char* kSpecs[] = {
  // generic
  "{}", "{:}", "{:>8}", "{:<8}", "{:^8}", "{:#}", "{:+}", "{: }",
  // integers
  "{:#x}", "{:#X}", "{:#o}", "{:b}", "{:B}", "{:08}", "{:>16}", "{:<16}",
  // floats
  "{:.0f}", "{:.3f}", "{:.6g}", "{:.3e}", "{:.3a}", "{:#.0f}", "{:#.0e}",
  // strings / chars
  "{:.5}", "{:>10.5}", "{:<10.5}"
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size < 1) return 0;

  size_t p = 0;
  auto next = [&]() -> uint8_t { return p < size ? data[p++] : 0; };

  std::string buf;
  buf.reserve(256);

  const char* spec = kSpecs[next() % (sizeof(kSpecs)/sizeof(kSpecs[0]))];

  auto rd_u32 = [&]() -> uint32_t {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= (uint32_t(next()) << (8 * i));
    return v;
  };
  auto rd_i64 = [&]() -> long long {
    uint64_t hi = static_cast<uint64_t>(rd_u32());
    uint64_t lo = static_cast<uint64_t>(rd_u32());
    return static_cast<long long>((hi << 32) | lo);
  };
  auto rd_double = [&]() -> double {
    return static_cast<double>(static_cast<int32_t>(rd_u32())) / 8192.0;
  };

  try {
    switch (next() % 6) {
      case 0: { long long v = rd_i64();
        fmt::format_to(std::back_inserter(buf), fmt::runtime(spec), v);
        break; }
      case 1: { uint32_t v = rd_u32();
        fmt::format_to(std::back_inserter(buf), fmt::runtime(spec), v);
        break; }
      case 2: { double v = rd_double();
        fmt::format_to(std::back_inserter(buf), fmt::runtime(spec), v);
        break; }
      case 3: { size_t n = std::min<size_t>(32, size - p);
        std::string s(reinterpret_cast<const char*>(data + p), n);
        p += n;
        fmt::format_to(std::back_inserter(buf), fmt::runtime(spec), s);
        break; }
      case 4: { char c = static_cast<char>(next());
        fmt::format_to(std::back_inserter(buf), fmt::runtime(spec), c);
        break; }
      default: {
        std::string tmp; tmp.reserve(64);
        double v = rd_double();
        (void)fmt::format_to_n(std::back_inserter(tmp), 32, fmt::runtime(spec), v);
        break; }
    }
  } catch (const fmt::format_error&) {
    // invalid spec/type combo — ignore and continue
  } catch (const std::exception&) {
    // extremely defensive: ignore any other throw and continue
  }

  try {
    long long a = rd_i64();
    double b = rd_double();
    auto args = fmt::make_format_args(a, b);         // needs lvalues
    fmt::vformat_to(std::back_inserter(buf), fmt::string_view("{} {}"), args);
  } catch (const fmt::format_error&) {
  } catch (const std::exception&) {
  }

  return 0;
}
