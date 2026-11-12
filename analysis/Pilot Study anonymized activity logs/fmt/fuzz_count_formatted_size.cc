// fuzz_count_formatted_size.cc (fixed)
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <limits>
#include <fmt/format.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size < 1) return 0;

  static const char* spec_pool[] = {
      "{}", "{:+}", "{: }", "{:#x}", "{:#X}", "{:#o}", "{:08}", "{:<12}",
      "{:>12}", "{:^12}", "{:.3f}", "{:.6g}", "{:b}", "{:B}"
  };
  constexpr size_t SPEC_COUNT = sizeof(spec_pool) / sizeof(spec_pool[0]);

  std::string fmt_s;
  size_t p = 0;
  unsigned fields = 1u + (data[p++] % 4u);

  for (unsigned i = 0; i < fields; ++i) {
    uint8_t byte = (p < size) ? data[p++] : 0;
    size_t idx = static_cast<size_t>(byte) % SPEC_COUNT;
    fmt_s += spec_pool[idx];
    if (i + 1 < fields) fmt_s += ' ';
  }

  auto rd_u32 = [&](uint32_t def = 0u) {
    if (p + 4 <= size) {
      uint32_t v = (uint32_t(data[p])      ) |
                   (uint32_t(data[p+1])<<8 ) |
                   (uint32_t(data[p+2])<<16) |
                   (uint32_t(data[p+3])<<24);
      p += 4; return v;
    }
    return def;
  };
  auto rd_i64 = [&]() -> long long {
    uint64_t hi = static_cast<uint64_t>(rd_u32());
    uint64_t lo = static_cast<uint64_t>(rd_u32());
    return static_cast<long long>((hi << 32) | lo);
  };
  auto rd_double = [&]() -> double {
    return double(int32_t(rd_u32())) / 131072.0;
  };

  try {
    switch (data[0] % 4) {
      case 0:
        (void)fmt::formatted_size(fmt::runtime(fmt_s), rd_i64(), rd_i64(),
                                  rd_u32(), rd_double());
        break;
      case 1: {
        int vi  = static_cast<int>(int32_t(rd_u32()));
        unsigned vu = rd_u32();
        long long vll = rd_i64();
        (void)fmt::formatted_size(fmt::runtime(fmt_s), vi, vu, vll);
        break;
      }
      case 2:
        (void)fmt::formatted_size(fmt::runtime(fmt_s),
                                  rd_double(), rd_double(), rd_double());
        break;
      default: {
        size_t n = (p < size) ? std::min<size_t>(size - p, 32) : 0;
        std::string s(reinterpret_cast<const char*>(data + p), n);
        char c = s.empty() ? '*' : s[0];
        (void)fmt::formatted_size(fmt::runtime(fmt_s), s, c,
                                  rd_i64(), rd_double());
        break;
      }
    }
  } catch (const fmt::format_error&) {
    // Invalid spec/arg combo → skip input without crashing
  } catch (const std::exception&) {
    // Extra safety net
  }

  return 0;
}

