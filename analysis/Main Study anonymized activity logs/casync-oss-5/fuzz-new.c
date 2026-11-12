#include <errno.h>
#include <syslog.h>
#include <string.h>
#include "cachunker.h"
#include "fuzz.h"
#include "log.h"
#include "util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        CaChunker chunker = CA_CHUNKER_INIT;
        int r;
        
        if (size < 10)
                return 0;

        if (!getenv("CASYNC_LOG_LEVEL"))
                set_log_level(LOG_CRIT);

        size_t min_size = (data[0] % 16 + 1) * 1024;
        size_t avg_size = (data[1] % 64 + 16) * 1024;
        size_t max_size = (data[2] % 128 + 64) * 1024;
        
        const uint8_t *input_data = data + 3;
        size_t input_size = size - 3;


        r = ca_chunker_set_size(&chunker, min_size, avg_size, max_size);
        if (r < 0)
                return 0;

        size_t offset = 0;
        while (offset < input_size) {
                size_t remaining = input_size - offset;
                size_t scan_size = remaining > 8192 ? 8192 : remaining;
                
                size_t boundary = ca_chunker_scan(&chunker, input_data + offset, scan_size);
                
                if (boundary == (size_t) -1) {
                        offset += scan_size;
                } else {
                        offset += boundary;
                        CaChunker new_chunker = CA_CHUNKER_INIT;
                        chunker = new_chunker;
                        ca_chunker_set_size(&chunker, min_size, avg_size, max_size);
                }
                
                if (offset >= input_size)
                        break;
        }

        if (input_size >= CA_CHUNKER_WINDOW_SIZE) {
                CaChunker test_chunker = CA_CHUNKER_INIT;
                ca_chunker_start(&test_chunker, input_data, CA_CHUNKER_WINDOW_SIZE);
                
                for (size_t i = CA_CHUNKER_WINDOW_SIZE; i < input_size && i < CA_CHUNKER_WINDOW_SIZE + 100; i++) {
                        ca_chunker_roll(&test_chunker, input_data[i - CA_CHUNKER_WINDOW_SIZE], input_data[i]);
                }
        }

        return 0;
}