#include "rar.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstring>

// Maximum argument length to prevent buffer overflows
#define MAX_ARG_LENGTH 1024
#define MAX_ARGS 256

// Helper to reset global state if needed.
// In many versions of Unrar, ErrHandler is a global object that needs cleaning.
void ResetGlobalState() {
    ErrHandler.Clean();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Use unique_ptr for automatic cleanup in case of exceptions
    std::unique_ptr<CommandData> Cmd(new CommandData);
    
    // Properly null-terminate the Command array
    // Ensure the entire Command buffer is cleared, not just first element
    memset(Cmd->Command, 0, sizeof(Cmd->Command));
    
    // Limit input size to prevent excessive processing
    size_t safe_size = (size > MAX_ARG_LENGTH * MAX_ARGS) ? MAX_ARG_LENGTH * MAX_ARGS : size;
    
    // Create a null-terminated C string from input data
    std::string raw_input(reinterpret_cast<const char*>(data), safe_size);
    
    // Allocate buffer for wide string conversion
    std::vector<wchar_t> wide_buffer(safe_size + 1, 0);
    size_t converted = mbstowcs(wide_buffer.data(), raw_input.c_str(), safe_size);
    
    // If conversion failed, try simple casting as fallback
    if (converted == (size_t)-1) {
        for (size_t i = 0; i < safe_size && i < wide_buffer.size() - 1; i++) {
            wide_buffer[i] = static_cast<wchar_t>(static_cast<unsigned char>(raw_input[i]));
        }
        wide_buffer[safe_size] = 0;
    }
    
    std::wstring global_args(wide_buffer.data());
    
    // Store arguments in a vector to maintain lifetime
    std::vector<std::vector<wchar_t>> arg_storage;
    arg_storage.reserve(MAX_ARGS);
    
    // Tokenize manually by spaces to simulate argv parsing
    size_t pos = 0;
    size_t arg_count = 0;
    
    while (pos < global_args.size() && arg_count < MAX_ARGS) {
        size_t next_space = global_args.find(L' ', pos);
        if (next_space == std::wstring::npos) {
            next_space = global_args.size();
        }
        
        if (next_space > pos) {
            size_t arg_len = next_space - pos;
            
            // Limit individual argument length
            if (arg_len > MAX_ARG_LENGTH) {
                arg_len = MAX_ARG_LENGTH;
            }
            
            std::wstring arg = global_args.substr(pos, arg_len);
            
            // Store argument in a buffer that persists
            std::vector<wchar_t> arg_buffer(arg.begin(), arg.end());
            arg_buffer.push_back(0); // Null terminate
            
            try {
                // Now we can safely pass the pointer as it's stored in arg_storage
                Cmd->ParseArg(arg_buffer.data());
                // Store the buffer AFTER ParseArg succeeds to maintain lifetime
                arg_storage.push_back(std::move(arg_buffer));
                arg_count++;
            } catch (const std::exception& e) {
                // More specific exception handling for debugging
                // During fuzzing, we want to continue but could log if needed
                (void)e; // Suppress unused variable warning
                break; // Stop processing this input on error
            } catch (...) {
                // Unknown exception, stop processing
                break;
            }
        }
        pos = next_space + 1;
    }
    
    // Trigger post-parsing validation
    try {
        Cmd->ParseDone();
    } catch (const std::exception& e) {
        // Catch specific exceptions but continue
        (void)e;
    } catch (...) {
        // Unknown exception
    }
    
    // unique_ptr automatically deletes Cmd, even if exceptions occur
    // No need for explicit delete
    
    ResetGlobalState();
    return 0;
}