#include <stddef.h>
#include <stdint.h>
#include <cassert>
#include <string>
#include <sys/uio.h>
#include "snappy.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    // Avoid self-crafted decompression bombs.
    size_t uncompressed_size;
    constexpr size_t kMaxUncompressedSize = 1 << 20;
    bool get_uncompressed_length_succeeded = snappy::GetUncompressedLength(
        input.data(), input.size(), &uncompressed_size);
    if (!get_uncompressed_length_succeeded ||
        (uncompressed_size > kMaxUncompressedSize) ||
        (uncompressed_size == 0)
    ) {
        return 0;
    }

    char* buf = new char[uncompressed_size];
    
    size_t iov_cnt = size & 0xff;
    if (iov_cnt == 0) {
        iov_cnt = 1;
    }
    if (iov_cnt > uncompressed_size) {
        iov_cnt = uncompressed_size;
    }
    iov_cnt = std::min(iov_cnt, size_t(256)); 

    size_t part = uncompressed_size / iov_cnt;
    size_t mod = uncompressed_size % iov_cnt;

    struct iovec* iov = new iovec[iov_cnt];
    size_t offset = 0;

    for (size_t i = 0; i < iov_cnt; ++i) {
        iov[i].iov_base = buf + offset;
        
        if (i < mod) {
            iov[i].iov_len = part + 1;
            offset += part + 1;
        } else {
            iov[i].iov_len = part;
            offset += part;
        }
    }

    snappy::RawUncompressToIOVec(input.data(), input.size(), iov, iov_cnt);

    delete[] iov;
    delete[] buf;
    return 0;
}

