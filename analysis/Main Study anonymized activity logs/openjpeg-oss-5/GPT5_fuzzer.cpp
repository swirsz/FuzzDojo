#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "openjpeg.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    const uint8_t* data;
    size_t         size;
    size_t         pos;
} MemFile;

/* --- Logging callbacks --- */

static void ErrorCallback(const char* msg, void* client_data)
{
    (void)msg;
    (void)client_data;
}

static void WarningCallback(const char* msg, void* client_data)
{
    (void)msg;
    (void)client_data;
}

static void InfoCallback(const char* msg, void* client_data)
{
    (void)msg;
    (void)client_data;
}

/* --- Stream callbacks over in-memory buffer --- */

static OPJ_SIZE_T ReadCallback(void* pBuffer, OPJ_SIZE_T nb_bytes, void* pUserData)
{
    MemFile* mem = (MemFile*)pUserData;
    if (!mem || !pBuffer || nb_bytes == 0) {
        return (OPJ_SIZE_T)-1;
    }
    if (mem->pos >= mem->size) {
        return (OPJ_SIZE_T)-1; /* EOF */
    }

    size_t remaining = mem->size - mem->pos;
    if ((OPJ_SIZE_T)remaining < nb_bytes) {
        nb_bytes = (OPJ_SIZE_T)remaining;
    }

    memcpy(pBuffer, mem->data + mem->pos, (size_t)nb_bytes);
    mem->pos += (size_t)nb_bytes;

    if (nb_bytes == 0) {
        return (OPJ_SIZE_T)-1;
    }
    return nb_bytes;
}

static OPJ_OFF_T SkipCallback(OPJ_OFF_T nb_bytes, void* pUserData)
{
    MemFile* mem = (MemFile*)pUserData;
    if (!mem || nb_bytes < 0) {
        return (OPJ_OFF_T)-1;
    }

    size_t skip = (size_t)nb_bytes;
    if (skip > mem->size - mem->pos) {
        skip = mem->size - mem->pos;
    }
    mem->pos += skip;
    return (OPJ_OFF_T)skip;
}

static OPJ_BOOL SeekCallback(OPJ_OFF_T offset, void* pUserData)
{
    MemFile* mem = (MemFile*)pUserData;
    if (!mem || offset < 0 || (size_t)offset > mem->size) {
        return OPJ_FALSE;
    }
    mem->pos = (size_t)offset;
    return OPJ_TRUE;
}

/* --- Core fuzzing logic for a single codec format --- */

static void FuzzOneCodec(OPJ_CODEC_FORMAT format,
                         const uint8_t* data, size_t size,
                         const uint8_t* flags, size_t flags_len)
{
    if (!data || size == 0) {
        return;
    }

    opj_codec_t* codec = opj_create_decompress(format);
    if (!codec) {
        return;
    }

    opj_set_error_handler(codec,   ErrorCallback,   NULL);
    opj_set_warning_handler(codec, WarningCallback, NULL);
    opj_set_info_handler(codec,    InfoCallback,    NULL);

    opj_dparameters_t parameters;
    opj_set_default_decoder_parameters(&parameters);

    /* Drive a few decoder parameters from tail bytes */
    if (flags_len >= 1) parameters.cp_reduce      = flags[0] & 0x1F;
    if (flags_len >= 2) parameters.cp_layer       = flags[1] & 0x1F;
    if (flags_len >= 3) parameters.jpwl_correct   = (flags[2] & 1);
    if (flags_len >= 4) parameters.jpwl_exp_comps = flags[3];
    if (flags_len >= 5) parameters.jpwl_max_tiles = flags[4];

    if (!opj_setup_decoder(codec, &parameters)) {
        opj_destroy_codec(codec);
        return;
    }

    opj_stream_t* stream = opj_stream_create(1024, OPJ_TRUE);
    if (!stream) {
        opj_destroy_codec(codec);
        return;
    }

    MemFile mem;
    mem.data = data;
    mem.size = size;
    mem.pos  = 0;

    opj_stream_set_user_data(stream, &mem, NULL);
    opj_stream_set_user_data_length(stream, size);
    opj_stream_set_read_function(stream, ReadCallback);
    opj_stream_set_skip_function(stream, SkipCallback);
    opj_stream_set_seek_function(stream, SeekCallback);

    opj_image_t* image = NULL;
    if (!opj_read_header(stream, codec, &image) || !image) {
        if (image) {
            opj_image_destroy(image);
        }
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        return;
    }

    opj_codestream_info_v2_t* info = opj_get_cstr_info(codec);
    if (info) {
        opj_destroy_cstr_info(&info);
    }

    OPJ_UINT32 width  = image->x1 - image->x0;
    OPJ_UINT32 height = image->y1 - image->y0;

    if (width == 0 || height == 0 || image->numcomps == 0) {
        opj_image_destroy(image);
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        return;
    }

    /* Clamp very large images to avoid huge allocations */
    const uint64_t kMaxPixels = 20000000ULL; /* ~20M pixels */
    uint64_t pixels = (uint64_t)width * (uint64_t)height;
    if (pixels > kMaxPixels || image->numcomps > 16) {
        opj_image_destroy(image);
        opj_stream_destroy(stream);
        opj_destroy_codec(codec);
        return;
    }

    /* Choose decode mode (full vs tiles) from flags */
    int use_tiles = (flags_len >= 6) ? (flags[5] & 1) : 0;

    /* Optionally fuzz decode area (sub-rectangle) */
    if (flags_len >= 10) {
        OPJ_UINT32 max_w = width;
        OPJ_UINT32 max_h = height;

        OPJ_UINT32 subw = 1u + (flags[6] % (max_w ? max_w : 1u));
        if (subw > max_w) subw = max_w;
        OPJ_UINT32 subh = 1u + (flags[7] % (max_h ? max_h : 1u));
        if (subh > max_h) subh = max_h;

        OPJ_UINT32 startx_range = max_w - subw;
        OPJ_UINT32 starty_range = max_h - subh;

        OPJ_UINT32 startx = image->x0 +
                            (startx_range ? (flags[8] % (startx_range + 1u)) : 0u);
        OPJ_UINT32 starty = image->y0 +
                            (starty_range ? (flags[9] % (starty_range + 1u)) : 0u);

        OPJ_UINT32 endx = startx + subw;
        OPJ_UINT32 endy = starty + subh;

        (void)opj_set_decode_area(codec, image, startx, starty, endx, endy);
    }

    if (!use_tiles) {
        /* Whole-image decode */
        (void)opj_decode(codec, stream, image);
    } else {
        /* Tile-based decode path */
        const OPJ_UINT32 kMaxTileBytes = 100u * 1024u * 1024u; /* 100 MB cap */
        OPJ_BOOL go_on = OPJ_TRUE;

        while (go_on) {
            OPJ_UINT32 tile_index = 0;
            OPJ_UINT32 tile_size  = 0;
            OPJ_INT32  tx0 = 0, ty0 = 0, tx1 = 0, ty1 = 0;
            OPJ_UINT32 nb_comps = 0;

            if (!opj_read_tile_header(codec, stream,
                                      &tile_index,
                                      &tile_size,
                                      &tx0, &ty0, &tx1, &ty1,
                                      &nb_comps,
                                      &go_on)) {
                break;
            }

            if (!go_on || tile_size == 0 || tile_size > kMaxTileBytes) {
                break;
            }

            OPJ_BYTE* tile_buf = (OPJ_BYTE*)malloc((size_t)tile_size);
            if (!tile_buf) {
                break;
            }

            (void)tx0; (void)ty0; (void)tx1; (void)ty1; (void)nb_comps;
            (void)opj_decode_tile_data(codec, tile_index, tile_buf, tile_size, stream);
            free(tile_buf);
        }
    }

    opj_codestream_index_t* index = opj_get_cstr_index(codec);
    if (index) {
        opj_destroy_cstr_index(&index);
    }

    (void)opj_end_decompress(codec, stream);

    opj_stream_destroy(stream);
    opj_destroy_codec(codec);
    opj_image_destroy(image);
}

/* --- libFuzzer entry points --- */

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/)
{
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size < 2) {
        return 0;
    }

    /* Use tail bytes as configuration / flags. */
    uint8_t flags[16];
    size_t  flags_len = (size < sizeof(flags)) ? size : sizeof(flags);
    memcpy(flags, data + (size - flags_len), flags_len);

    /* Fuzz all three relevant codec types with the same input. */
    static const OPJ_CODEC_FORMAT kFormats[] = {
        OPJ_CODEC_J2K, /* raw codestream */
        OPJ_CODEC_JP2, /* JP2 container */
        OPJ_CODEC_JPT  /* JPT/JPIP stream */
    };

    for (size_t i = 0; i < sizeof(kFormats) / sizeof(kFormats[0]); ++i) {
        FuzzOneCodec(kFormats[i], data, size, flags, flags_len);
    }

    return 0;
}