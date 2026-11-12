#include <boost/uuid/uuid.hpp>
#include <boost/uuid/name_generator_md5.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_clock.hpp>
#include <boost/uuid/detail/numeric_cast.hpp>

#include <cstdint>
#include <string>
#include <sstream>
#include <limits>
#include <stdexcept>
#include <type_traits>

using namespace boost::uuids;

// Helper: safe fuzz slice
template <typename T>
T load_integral(const uint8_t* data, size_t size, size_t offset) {
	if (offset + sizeof(T) > size) return T{};
	T value{};
	std::memcpy(&value, data + offset, sizeof(T));
	return value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) return 0;

	// ---- numeric_cast.hpp ----
	{
		uint64_t u64 = load_integral<uint64_t>(data, size, 0);
		try {
			(void)boost::uuids::detail::numeric_cast<uint32_t>(u64);
		} catch (...) {}
		try {
			(void)boost::uuids::detail::numeric_cast<uint16_t>(u64);
		} catch (...) {}
		try {
			(void)boost::uuids::detail::numeric_cast<uint8_t>(u64);
		} catch (...) {}
	}

	// ---- nil_generator.hpp ----
	{
		try {
			nil_generator ng;
			uuid nil = ng();
			std::ostringstream oss;
			oss << nil; // should always be 00000000-0000-0000-0000-000000000000
			(void)oss.str();
		} catch(...) {}
	}

	// ---- uuid_clock.hpp ----
	{
		try {
			auto t1 = uuid_clock::now();
			auto t2 = uuid_clock::now();
			(void)(t1 <= t2); // exercise operators
			(void)(t1 == t2);
			auto duration = t2 - t1;
			(void)duration.count();
		} catch(...) {}
	}

	// ---- name_generator_md5.hpp ----
	{
		try {
			// Use some input bytes as "namespace"
			uuid ns = string_generator()("6ba7b810-9dad-11d1-80b4-00c04fd430c8"); // DNS namespace
			name_generator_md5 gen(ns);

			std::string input(reinterpret_cast<const char*>(data), size);
			uuid u = gen(input);

			std::ostringstream oss;
			oss << u;
			(void)oss.str();
		} catch(...) {}
	}

	return 0;
}

