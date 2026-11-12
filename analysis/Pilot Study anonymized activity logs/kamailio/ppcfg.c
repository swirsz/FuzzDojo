#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "./core/ppcfg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;

    /* allocate copy with project allocator */
    char *buf = malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    pp_substdef_add(data, 0);
    pp_subst_run(&buf);
    pp_define_core();
    free(buf);

    return 0;
}
