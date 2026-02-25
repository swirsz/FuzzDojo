#include <stddef.h>
#include <stdint.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>
#include <unistd.h>
#include <cstring>
#include "rar.hpp"

namespace fs = std::filesystem;

// Prevent disk I/O pollution in fuzzing
static bool g_initialized = false;
static std::string g_temp_dir;

static void InitializeFuzzer() {
    if (g_initialized) return;
    g_initialized = true;
    
    // Create isolated temp directory for fuzzer
    char tmpl[] = "/tmp/unrar_fuzz_XXXXXX";
    if (mkdtemp(tmpl)) {
        g_temp_dir = tmpl;
        // Change to temp dir to contain file operations
        chdir(g_temp_dir.c_str());
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitializeFuzzer();
    
    // Need at least 2 bytes: flags + minimal data
    if (size < 2) return 0;
    
    // Extract fuzzing parameters from first byte
    uint8_t flags = data[0];
    bool preprocess = (flags & 0x01) != 0;
    bool use_archive = (flags & 0x02) != 0;
    uint8_t arg_strategy = (flags >> 2) & 0x03; // 4 strategies
    
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;
    
    // Strategy 0: Parse arguments from fuzzer data
    // Strategy 1: Fixed command with fuzzer as archive path
    // Strategy 2: Mixed approach
    
    std::vector<std::string> args;
    args.emplace_back("unrar"); // More realistic argv[0]
    
    switch (arg_strategy) {
        case 0: {
            // Parse null-delimited arguments
            size_t pos = 0;
            while (pos < payload_size) {
                size_t end = pos;
                // Find next delimiter or end, limit arg length
                while (end < payload_size && end - pos < 256 && 
                       payload[end] != '\0' && payload[end] != '\n') {
                    end++;
                }
                if (end > pos) {
                    args.emplace_back(reinterpret_cast<const char*>(payload + pos), end - pos);
                }
                pos = end + 1;
            }
            break;
        }
        case 1: {
            // Fixed extraction command with fuzzer-generated archive
            if (use_archive && payload_size > 0) {
                std::string archive_path = g_temp_dir + "/test.rar";
                std::ofstream ofs(archive_path, std::ios::binary);
                if (ofs) {
                    ofs.write(reinterpret_cast<const char*>(payload), payload_size);
                    ofs.close();
                    args.emplace_back("x");
                    args.emplace_back("-y"); // Assume yes
                    args.emplace_back(archive_path);
                }
            }
            break;
        }
        case 2: {
            // Common commands with fuzzer data
            const char* commands[] = {"e", "x", "l", "t", "p", "v"};
            if (payload_size > 0) {
                args.emplace_back(commands[payload[0] % 6]);
                if (payload_size > 1) {
                    args.emplace_back(std::string(reinterpret_cast<const char*>(payload + 1), 
                                                  std::min(payload_size - 1, size_t(64))));
                }
            }
            break;
        }
    }
    
    // Ensure we have at least a command
    if (args.size() < 2) {
        args.emplace_back("l");
    }
    
    // Build argv (use const_cast as CommandData expects char**)
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& s : args) {
        argv.push_back(const_cast<char*>(s.c_str()));
    }
    argv.push_back(nullptr); // Null terminator
    
    int argc = static_cast<int>(args.size());
    
    // Fuzzing target
    CommandData cmd;
    try {
        cmd.ParseCommandLine(preprocess, argc, argv.data());
        
        // If parsing succeeded, try executing (if safe)
        // Note: Only enable if CommandData::ProcessCommand is safe for fuzzing
        // cmd.ProcessCommand();
        
    } catch (const std::exception& e) {
        // Catch standard exceptions but don't report them
        (void)e;
    } catch (...) {
        // Catch all other exceptions
    }
    
    // Cleanup any generated files periodically
    static int call_count = 0;
    if (++call_count % 1000 == 0 && !g_temp_dir.empty()) {
        // Clean up temp directory
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(g_temp_dir, ec)) {
            fs::remove_all(entry.path(), ec);
        }
    }
    
    return 0;
}

// Cleanup on fuzzer shutdown
extern "C" int LLVMFuzzerFinalize() {
    if (!g_temp_dir.empty()) {
        std::error_code ec;
        fs::remove_all(g_temp_dir, ec);
    }
    return 0;
}