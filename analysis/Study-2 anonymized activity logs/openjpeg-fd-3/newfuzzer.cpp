// improved_fuzz_opj_roundtrip.cpp
// Fixed version with proper error handling, overflow checks, and fuzzer-driven parameters

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "openjpeg.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

#define NUM_COMPS_MAX 4
#define MAX_DIMENSION 2048
#define MIN_INPUT_SIZE 32

static INLINE OPJ_UINT32 opj_uint_max(OPJ_UINT32 a, OPJ_UINT32 b)
{
    return (a > b) ? a : b;
}

static INLINE OPJ_UINT32 opj_uint_min(OPJ_UINT32 a, OPJ_UINT32 b)
{
    return (a < b) ? a : b;
}

static void error_callback(const char *msg, void *client_data)
{
    (void)client_data;
    (void)msg;
    // Suppress output during fuzzing
}

static void warning_callback(const char *msg, void *client_data)
{
    (void)client_data;
    (void)msg;
    // Suppress output during fuzzing
}

static void info_callback(const char *msg, void *client_data)
{
    (void)client_data;
    (void)msg;
    // Suppress output during fuzzing
}

int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/)
{
    return 0;
}

// Safe multiplication with overflow check
static bool safe_multiply(OPJ_UINT32 a, OPJ_UINT32 b, OPJ_UINT32* result)
{
    if (a == 0 || b == 0) {
        *result = 0;
        return true;
    }
    if (a > UINT32_MAX / b) {
        return false; // Overflow
    }
    *result = a * b;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    // Need at least some bytes to derive parameters
    if (!buf || len < MIN_INPUT_SIZE) {
        return 0;
    }

    // Derive parameters from fuzzer input
    size_t offset = 0;
    
    // Extract parameters from first bytes
    OPJ_UINT32 num_comps = (buf[offset++] % 3) + 1; // 1-3 components
    if (num_comps > NUM_COMPS_MAX) num_comps = NUM_COMPS_MAX;
    
    OPJ_UINT32 image_width = ((buf[offset++] % 64) + 1) * 8; // 8-512, multiples of 8
    OPJ_UINT32 image_height = ((buf[offset++] % 64) + 1) * 8; // 8-512, multiples of 8
    OPJ_UINT32 tile_width = ((buf[offset++] % 32) + 1) * 8; // 8-256, multiples of 8
    OPJ_UINT32 tile_height = ((buf[offset++] % 32) + 1) * 8; // 8-256, multiples of 8
    OPJ_UINT32 comp_prec = ((buf[offset++] % 2) + 1) * 8; // 8 or 16 bits
    OPJ_UINT32 irreversible = buf[offset++] % 2; // 0 or 1
    OPJ_UINT32 numresolution = (buf[offset++] % 5) + 2; // 2-6
    
    // Clamp dimensions to reasonable values
    if (image_width > MAX_DIMENSION) image_width = MAX_DIMENSION;
    if (image_height > MAX_DIMENSION) image_height = MAX_DIMENSION;
    if (tile_width > image_width) tile_width = image_width;
    if (tile_height > image_height) tile_height = image_height;
    
    OPJ_UINT32 offsetx = 0;
    OPJ_UINT32 offsety = 0;

    // Calculate number of tiles with overflow check
    OPJ_UINT32 l_nb_tiles_width, l_nb_tiles_height, l_nb_tiles;
    
    l_nb_tiles_width = (offsetx + image_width + tile_width - 1) / tile_width;
    l_nb_tiles_height = (offsety + image_height + tile_height - 1) / tile_height;
    
    if (!safe_multiply(l_nb_tiles_width, l_nb_tiles_height, &l_nb_tiles)) {
        return 0; // Overflow
    }
    
    // Sanity check on number of tiles
    if (l_nb_tiles > 256) {
        return 0; // Too many tiles
    }

    // Calculate data size with overflow checks
    OPJ_UINT32 temp1, temp2, temp3, l_data_size;
    if (!safe_multiply(tile_width, tile_height, &temp1)) return 0;
    if (!safe_multiply(temp1, num_comps, &temp2)) return 0;
    if (!safe_multiply(temp2, (comp_prec / 8), &l_data_size)) return 0;
    
    // Check if we have enough input data
    if (len < offset + l_data_size) {
        return 0; // Not enough data
    }

    // Allocate buffer
    OPJ_BYTE* l_data = (OPJ_BYTE*)malloc(l_data_size * sizeof(OPJ_BYTE));
    if (l_data == NULL) {
        return 0; // Allocation failed
    }

    // Copy fuzzer data into buffer
    memcpy(l_data, buf + offset, l_data_size);

    // Setup encoder parameters
    opj_cparameters_t l_param;
    opj_set_default_encoder_parameters(&l_param);
    
    l_param.tcp_numlayers = 1;
    l_param.cp_fixed_quality = 1;
    l_param.tcp_distoratio[0] = 20;
    l_param.cp_tx0 = 0;
    l_param.cp_ty0 = 0;
    l_param.tile_size_on = OPJ_TRUE;
    l_param.cp_tdx = tile_width;
    l_param.cp_tdy = tile_height;
    l_param.cblockw_init = 64;
    l_param.cblockh_init = 64;
    l_param.irreversible = irreversible;
    l_param.numresolution = numresolution;
    l_param.prog_order = OPJ_LRCP;

    // Setup image component parameters
    opj_image_cmptparm_t l_params[NUM_COMPS_MAX];
    for (OPJ_UINT32 i = 0; i < num_comps; ++i) {
        l_params[i].dx = 1;
        l_params[i].dy = 1;
        l_params[i].h = image_height;
        l_params[i].w = image_width;
        l_params[i].sgnd = 0;
        l_params[i].prec = comp_prec;
        l_params[i].x0 = offsetx;
        l_params[i].y0 = offsety;
    }

    // Create codec
    opj_codec_t* l_codec = opj_create_compress(OPJ_CODEC_J2K);
    if (!l_codec) {
        free(l_data);
        return 0;
    }

    // Set handlers (suppress output)
    opj_set_info_handler(l_codec, info_callback, NULL);
    opj_set_warning_handler(l_codec, warning_callback, NULL);
    opj_set_error_handler(l_codec, error_callback, NULL);

    // Create image
    opj_image_t* l_image = opj_image_tile_create(num_comps, l_params, OPJ_CLRSPC_SRGB);
    if (!l_image) {
        opj_destroy_codec(l_codec);
        free(l_data);
        return 0;
    }

    l_image->x0 = offsetx;
    l_image->y0 = offsety;
    l_image->x1 = offsetx + image_width;
    l_image->y1 = offsety + image_height;
    l_image->color_space = OPJ_CLRSPC_SRGB;

    // Setup encoder
    if (!opj_setup_encoder(l_codec, &l_param, l_image)) {
        opj_image_destroy(l_image);
        opj_destroy_codec(l_codec);
        free(l_data);
        return 0;
    }

    // Create stream to /dev/null (no file creation)
    opj_stream_t* l_stream = opj_stream_create_default_file_stream("/dev/null", OPJ_FALSE);
    if (!l_stream) {
        opj_image_destroy(l_image);
        opj_destroy_codec(l_codec);
        free(l_data);
        return 0;
    }

    // Start compression
    if (!opj_start_compress(l_codec, l_image, l_stream)) {
        opj_stream_destroy(l_stream);
        opj_image_destroy(l_image);
        opj_destroy_codec(l_codec);
        free(l_data);
        return 0;
    }

    // Write tiles
    for (OPJ_UINT32 i = 0; i < l_nb_tiles; ++i) {
        OPJ_UINT32 tile_y = i / l_nb_tiles_width;
        OPJ_UINT32 tile_x = i % l_nb_tiles_width;
        OPJ_UINT32 tile_x0 = opj_uint_max(l_image->x0, tile_x * tile_width);
        OPJ_UINT32 tile_y0 = opj_uint_max(l_image->y0, tile_y * tile_height);
        OPJ_UINT32 tile_x1 = opj_uint_min(l_image->x1, (tile_x + 1) * tile_width);
        OPJ_UINT32 tile_y1 = opj_uint_min(l_image->y1, (tile_y + 1) * tile_height);
        
        // Calculate tile size with overflow check
        OPJ_UINT32 tile_w = tile_x1 - tile_x0;
        OPJ_UINT32 tile_h = tile_y1 - tile_y0;
        OPJ_UINT32 tilesize;
        
        if (!safe_multiply(tile_w, tile_h, &temp1)) break;
        if (!safe_multiply(temp1, num_comps, &temp2)) break;
        if (!safe_multiply(temp2, (comp_prec / 8), &tilesize)) break;
        
        if (tilesize > l_data_size) {
            tilesize = l_data_size; // Clamp to available data
        }
        
        if (!opj_write_tile(l_codec, i, l_data, tilesize, l_stream)) {
            // Write failed, but continue to cleanup
            break;
        }
    }

    // End compression (may fail, ignore result)
    opj_end_compress(l_codec, l_stream);

    // Cleanup
    opj_stream_destroy(l_stream);
    opj_destroy_codec(l_codec);
    opj_image_destroy(l_image);
    free(l_data);

    return 0;
}