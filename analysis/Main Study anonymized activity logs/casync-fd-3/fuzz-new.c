/* SPDX-License-Identifier: LGPL-2.1+ */
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "compressor.h"
#include "fuzz.h"
#include "log.h"
#include "util.h"
#include "cachunk.h"
#include "def.h"

typedef struct header {
        uint32_t alg;
        uint32_t reserved[5]; /* Extra space to keep fuzz cases stable in case we need to
                               * add stuff in the future. */
        uint8_t data[];
} header;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(realloc_buffer_free) ReallocBuffer rb = {}, rb2 = {};
        const char *d;
        char *path = NULL;
        _cleanup_(safe_closep) int fd = -1;
        int r;
        
        /* Add reasonable size limit to prevent resource exhaustion */
        if (size > 1024 * 1024) { /* 1MB limit */
                return 0;
        }
        
        /* Get temp directory */
        if (var_tmp_dir(&d) < 0) {
                return 0;
        }
        
        path = strjoina(d, "/chunk-test.XXXXXX");
        
        /* Create temporary file */
        fd = mkostemp(path, O_RDWR|O_CLOEXEC);
        if (fd < 0) {
                return 0;
        }
        
        /* Save and compress data to file */
        r = ca_save_and_compress_fd(fd, CA_COMPRESSION_DEFAULT, data, size);
        if (r < 0) {
                goto cleanup;
        }
        
        /* Seek back to beginning - proper error checking */
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                goto cleanup;
        }
        
        /* Load and decompress from file */
        r = ca_load_and_decompress_fd(fd, &rb);
        if (r < 0) {
                goto cleanup;
        }
        
        /* Validate decompressed size matches original */
        if (realloc_buffer_size(&rb) != size) {
                goto cleanup;
        }
        
        /* Validate decompressed content matches original */
        if (size > 0 && memcmp(realloc_buffer_data(&rb), data, size) != 0) {
                goto cleanup;
        }
        
        /* Test direct compression/decompression without file I/O */
        realloc_buffer_empty(&rb);
        r = ca_compress(CA_COMPRESSION_DEFAULT, data, size, &rb);
        if (r < 0) {
                goto cleanup;
        }
        
        /* Check that compression produced some output */
        if (realloc_buffer_size(&rb) == 0 && size > 0) {
                goto cleanup;
        }
        
        /* Decompress and validate */
        r = ca_decompress(realloc_buffer_data(&rb), realloc_buffer_size(&rb), &rb2);
        if (r < 0) {
                goto cleanup;
        }
        
        /* Validate round-trip compression/decompression */
        if (realloc_buffer_size(&rb2) != size) {
                goto cleanup;
        }
        
        if (size > 0 && memcmp(realloc_buffer_data(&rb2), data, size) != 0) {
                goto cleanup;
        }

cleanup:
        /* Always unlink temporary file before closing fd */
        if (path != NULL) {
                (void) unlink(path);
        }
        
        /* fd will be closed automatically by _cleanup_(safe_closep) */
        /* rb and rb2 will be freed automatically by _cleanup_(realloc_buffer_free) */
        
        return 0;
}