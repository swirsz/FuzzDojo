/*
 * Copyright (c) 2025, OpenJPEG Fuzzing Driver
 * Target: j2k.c, jp2.c (Dump, Info, and Indexing paths)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openjpeg.h"

/* * DEFINITIONS FOR DUMPING
 * These macros are internal to OpenJPEG (j2k.h) but required for the dump function.
 */
#ifndef OPJ_J2K_MH_INFO
#define OPJ_J2K_MH_INFO      0x0001 /**< main header info */
#endif
#ifndef OPJ_J2K_TH_INFO
#define OPJ_J2K_TH_INFO      0x0002 /**< tile header info */
#endif
#ifndef OPJ_J2K_TCH_INFO
#define OPJ_J2K_TCH_INFO     0x0004 /**< tile part header info */
#endif
#ifndef OPJ_IMG_INF
#define OPJ_IMG_INFO         0x0020 /**< image info */
#endif

/* Dummy callback handlers - suppress output to speed up fuzzing */
static void error_callback(const char *msg, void *client_data) {
    (void)msg;
    (void)client_data;
}

static void warning_callback(const char *msg, void *client_data) {
    (void)msg;
    (void)client_data;
}

static void info_callback(const char *msg, void *client_data) {
    (void)msg;
    (void)client_data;
}

/* Struct to hold our memory stream state */
typedef struct {
    const uint8_t *pData;
    OPJ_SIZE_T dataSize;
    OPJ_SIZE_T offset;
} opj_memory_stream_t;

/* Memory stream read function */
static OPJ_SIZE_T opj_memory_stream_read(void * p_buffer, OPJ_SIZE_T p_nb_bytes, void * p_user_data) {
    opj_memory_stream_t* l_stream = (opj_memory_stream_t*)p_user_data;
    OPJ_SIZE_T l_nb_bytes_read = p_nb_bytes;

    if (l_stream->offset >= l_stream->dataSize) {
        return (OPJ_SIZE_T)-1;
    }

    if (p_nb_bytes > (l_stream->dataSize - l_stream->offset)) {
        l_nb_bytes_read = l_stream->dataSize - l_stream->offset;
    }

    memcpy(p_buffer, l_stream->pData + l_stream->offset, l_nb_bytes_read);
    l_stream->offset += l_nb_bytes_read;

    return l_nb_bytes_read;
}

/* Memory stream skip function */
static OPJ_OFF_T opj_memory_stream_skip(OPJ_OFF_T p_nb_bytes, void * p_user_data) {
    opj_memory_stream_t* l_stream = (opj_memory_stream_t*)p_user_data;

    if (p_nb_bytes < 0) {
        if (l_stream->offset < (OPJ_SIZE_T)-p_nb_bytes) {
            l_stream->offset = 0;
        } else {
            l_stream->offset -= (OPJ_SIZE_T)-p_nb_bytes;
        }
        return p_nb_bytes;
    }

    if (l_stream->offset + (OPJ_SIZE_T)p_nb_bytes > l_stream->dataSize) {
        OPJ_SIZE_T l_nb_bytes_skipped = l_stream->dataSize - l_stream->offset;
        l_stream->offset = l_stream->dataSize;
        return (OPJ_OFF_T)l_nb_bytes_skipped;
    }

    l_stream->offset += (OPJ_SIZE_T)p_nb_bytes;
    return p_nb_bytes;
}

/* Memory stream seek function */
static OPJ_BOOL opj_memory_stream_seek(OPJ_OFF_T p_nb_bytes, void * p_user_data) {
    opj_memory_stream_t* l_stream = (opj_memory_stream_t*)p_user_data;

    if (p_nb_bytes < 0) {
        return OPJ_FALSE;
    }

    if ((OPJ_SIZE_T)p_nb_bytes > l_stream->dataSize) {
        return OPJ_FALSE;
    }

    l_stream->offset = (OPJ_SIZE_T)p_nb_bytes;
    return OPJ_TRUE;
}

/* Helper to create the stream */
static opj_stream_t* opj_stream_create_memory_stream(opj_memory_stream_t* p_memoryStream, OPJ_SIZE_T p_size, OPJ_BOOL p_is_read_stream) {
    opj_stream_t* l_stream;
    
    if (!p_memoryStream) return NULL;

    l_stream = opj_stream_default_create(p_is_read_stream);
    if (!l_stream) return NULL;

    opj_stream_set_read_function(l_stream, opj_memory_stream_read);
    opj_stream_set_skip_function(l_stream, opj_memory_stream_skip);
    opj_stream_set_seek_function(l_stream, opj_memory_stream_seek);
    opj_stream_set_user_data(l_stream, p_memoryStream, NULL);
    opj_stream_set_user_data_length(l_stream, p_size);

    return l_stream;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    opj_dparameters_t parameters;
    opj_codec_t* l_codec = NULL;
    opj_image_t* l_image = NULL;
    opj_stream_t* l_stream = NULL;
    opj_memory_stream_t l_mem_stream;
    opj_codestream_info_v2_t* cstr_info = NULL;
    opj_codestream_index_t* cstr_index = NULL;

    /* Require a minimal size for header detection */
    if (size < 12) {
        return 0;
    }

    /* 1. Setup Parameters */
    opj_set_default_decoder_parameters(&parameters);

    /* 2. Determine Format (J2K or JP2) */
    OPJ_CODEC_FORMAT l_codec_format = OPJ_CODEC_J2K;
    /* Check for JP2 signature */
    if (memcmp(data, "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a", 12) == 0) {
        l_codec_format = OPJ_CODEC_JP2;
    }

    /* 3. Initialize Codec */
    l_codec = opj_create_decompress(l_codec_format);
    if (!l_codec) {
        return 0;
    }

    /* Set handlers to suppress noise but catch logic errors */
    opj_set_info_handler(l_codec, info_callback, NULL);
    opj_set_warning_handler(l_codec, warning_callback, NULL);
    opj_set_error_handler(l_codec, error_callback, NULL);

    if (!opj_setup_decoder(l_codec, &parameters)) {
        opj_destroy_codec(l_codec);
        return 0;
    }

    /* 4. Stream Setup */
    l_mem_stream.pData = data;
    l_mem_stream.dataSize = size;
    l_mem_stream.offset = 0;
    l_stream = opj_stream_create_memory_stream(&l_mem_stream, size, OPJ_TRUE);
    if (!l_stream) {
        opj_destroy_codec(l_codec);
        return 0;
    }

    /* 5. Read Header */
    if (opj_read_header(l_stream, l_codec, &l_image)) {
        
        /* * Coverage Target 1: Info and Indexing 
         * Get these immediately after header read while state is fresh.
         */
        cstr_info = opj_get_cstr_info(l_codec);
        if (cstr_info) {
            opj_destroy_cstr_info(&cstr_info);
        }

        cstr_index = opj_get_cstr_index(l_codec);
        if (cstr_index) {
            opj_destroy_cstr_index(&cstr_index);
        }

        /* * Coverage Target 2: Dump Codec
         * Dumps internal state structure strings.
         */
        FILE *dev_null = fopen("/dev/null", "w");
        if (dev_null) {
            opj_dump_codec(l_codec, OPJ_IMG_INFO | OPJ_J2K_MH_INFO | OPJ_J2K_TH_INFO, dev_null);
            fclose(dev_null);
        }

        /* * Coverage Target 3: Full Decode
         * FIX: We removed opj_get_decoded_tile. It conflicts with opj_decode
         * on the same codec instance and causes state corruption crashes.
         * opj_decode is sufficient to exercise the tile decoding logic internally.
         */
        if (l_image->x1 > l_image->x0 && l_image->y1 > l_image->y0) {
             
             /* Set decode area to full image */
             if (opj_set_decode_area(l_codec, l_image, l_image->x0, l_image->y0, l_image->x1, l_image->y1)) {
                 
                 if (opj_decode(l_codec, l_stream, l_image)) {
                     /* If successful, call end_decompress to finish state cleanup coverage */
                     opj_end_decompress(l_codec, l_stream);
                 }
             }
        }
    }

    /* Cleanup - Order is important: Stream, then Codec, then Image */
    if (l_stream) {
        opj_stream_destroy(l_stream);
        l_stream = NULL;
    }
    
    if (l_codec) {
        opj_destroy_codec(l_codec);
        l_codec = NULL;
    }
    
    if (l_image) {
        opj_image_destroy(l_image);
        l_image = NULL;
    }

    return 0;
}
