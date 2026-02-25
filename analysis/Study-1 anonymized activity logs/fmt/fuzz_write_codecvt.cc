// OSS-Fuzz target: hits detail::write_codecvt through write_encoded_tm_str.
//
// v12, C++14.
#include <cstdint>
#include <cstddef>
#include <string>
#include <locale>
#include <vector>
#include <iterator>

#include <fmt/chrono.h>  // detail::write_encoded_tm_str

// Some locales may not be present in the container; we try/catch and skip.
static std::vector<std::string> kLocales = {
    "C", "en_US.UTF-8", "ja_JP.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8"
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data) return 0;

  // Build an arbitrary (possibly invalid) byte sequence that we will attempt to
  // "encode" via the locale path. This is OK: the function must handle errors.
  std::string in(reinterpret_cast<const char*>(data),
                 std::min<size_t>(size, 64));

  // Try a few locales; whichever constructs will drive the path.
  for (const auto& name : kLocales) {
    try {
      std::locale loc(name.c_str());
      std::string out;
      out.reserve(256);
      (void)fmt::detail::write_encoded_tm_str(std::back_inserter(out),
                                              fmt::string_view(in), loc);
    } catch (...) {
      // Locale not installed or conversion facet throws; continue.
    }
  }
  return 0;
}

