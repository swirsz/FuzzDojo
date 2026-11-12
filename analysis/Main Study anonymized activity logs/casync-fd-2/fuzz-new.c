/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <syslog.h>

#include "compressor.h"
#include "cacompression.h"
#include "fuzz.h"
#include "log.h"
#include "util.h"

typedef struct header {
        uint32_t alg;
        uint32_t reserved[5]; /* Extra space to keep fuzz cases stable in case we need to
                               * add stuff in the future. */
        uint8_t data[];
} header;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ void *buf = NULL;
        int r;

        if (size < 2)
                return 0;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("CASYNC_LOG_LEVEL"))
                set_log_level(LOG_CRIT);

        CaCompressionType compression_type = (CaCompressionType)data[0];

        _cleanup_(compressor_finish) CompressorContext context = COMPRESSOR_CONTEXT_INIT;

        r = compressor_start_encode(&context, compression_type);
        if (r < 0) {
                log_debug_errno(r, "compressor_start_encode failed: %m");
                return 0;
        }

        log_info("Using compression %d, data size=%zu", compression_type, size);

        size_t out_size = MAX(size, 128u), /* Make the buffer a bit larger for very small data */
        ret_done;
        buf = malloc(out_size);
        if (!buf) {
                log_oom();
                return 0;
        }

        r = compressor_input(&context, data, size);
        if (r < 0) {
                log_debug_errno(r, "compressor_input failed: %m");
                return 0;
        }

        r = compressor_encode(&context, true, buf, out_size, &ret_done);
        if (r < 0) {
                log_debug_errno(r, "compressor_encode failed: %m");
                return 0;
        }

        return 0;
}
