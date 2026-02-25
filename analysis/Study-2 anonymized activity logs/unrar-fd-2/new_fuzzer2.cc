#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdlib>
#include <cstring>

#include <fuzzer/FuzzedDataProvider.h>

#include "rar.hpp"

// Helper to create a mutable wchar_t buffer from a std::string.
// Required because ParseArg takes a non-const wchar_t*
std::vector<wchar_t> MakeMutableArg(const std::string& str) {
    std::vector<wchar_t> buffer(str.size() + 1);
    std::mbstowcs(buffer.data(), str.c_str(), str.size() + 1);
    return buffer;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // 1. Setup the Environment
  // unrar's ReadConfig looks for ".rarrc" in the directory specified by HOME.
  // We set HOME to /tmp to ensure we have write permissions and isolation.
  const char* tmp_dir = "/tmp";
  setenv("HOME", tmp_dir, 1);

  // 2. Create the Configuration File
  // We write the fuzzed data to /tmp/.rarrc
  std::string config_path = std::string(tmp_dir) + "/.rarrc";
  std::string config_content = fdp.ConsumeRemainingBytesAsString();

  {
      std::ofstream config_file(config_path, std::ios::binary);
      config_file << config_content;
      config_file.close();
  }

  // 3. Setup CommandData
  CommandData Cmd;
  Cmd.Init();

  // 4. Pre-condition: Set a Command
  // The target code at line 254 checks 'if (!Command.empty())'.
  // We must set a command (like "t" for test) to reach the logic 
  // that parses command-specific switches (e.g., "switches_t=...").
  auto arg_command = MakeMutableArg("t");
  Cmd.ParseArg(arg_command.data());

  // 5. Trigger the Target
  // This will read /tmp/.rarrc and parse the switches inside it.
  try {
      Cmd.ReadConfig();
  } catch (...) {
      // Catch memory/parsing exceptions to keep the fuzzer alive
  }

  // 6. Cleanup
  unlink(config_path.c_str());

  return 0;
}
