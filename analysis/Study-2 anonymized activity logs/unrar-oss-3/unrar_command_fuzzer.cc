#include <stddef.h>
#include <stdint.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>
#include <unistd.h>

#include "rar.hpp"

namespace fs = std::__fs::filesystem;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size == 0) return 0;

	bool preprocess = (data[0] & 1) != 0;

	const uint8_t *arg_data = data + 1;

	size_t arg_size = size - 1;

	std::vector<std::string> args;
	args.emplace_back("unrar_command_fuzzer"); // argv[0]

	std::string current;
	for (size_t i = 0; i < arg_size; i++) {
		if (arg_data[i] == '\0' || arg_data[i] == ' ' || arg_data[i] == '\n') {
			if (!current.empty()) {
				args.push_back(current);
				current.clear();
			}
		} else {
			current.push_back(static_cast<char>(arg_data[i]));
		}
	}
	if (!current.empty()) {
		args.push_back(current);
	}

	// Build argv
	std::vector<char*> argv;
	argv.reserve(args.size());
	for (auto& s : args) {
		argv.push_back(s.data());
	}

	int argc = static_cast<int>(argv.size());

	CommandData cmd;
	try {
		cmd.ParseCommandLine(preprocess, argc, argv.data());
	} catch (...) {
		// Don’t crash fuzzer if target throws
	}

	return 0;
}
