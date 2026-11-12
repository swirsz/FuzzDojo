// fuzz_openjpeg.c
// Build (example):
// clang -fsanitize=fuzzer,address,undefined -g -O1 fuzz_openjpeg.c -lopenjp2 -o fuzz_openjpeg
// or with libFuzzer: clang -fsanitize=fuzzer,address,undefined ...

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openjpeg.h>

/* Small memory-stream wrapper used by many OpenJPEG examples */
typedef struct {
    OPJ_BYTE *pData;
    OPJ_SIZE_T dataSize;
    OPJ_SIZE_T offset;
} opj_memory_stream;

/* read from memory */
static OPJ_SIZE_T mem_read(void *buffer, OPJ_SIZE_T nb_bytes, void * p_user_data) {
    opj_memory_stream* m = (opj_memory_stream*) p_user_data;
    if (!m || m->offset >= m->dataSize) return (OPJ_SIZE_T)-1;
    OPJ_SIZE_T toread = nb_bytes;
    if (toread > (m->dataSize - m->offset)) toread = m->dataSize - m->offset;
    memcpy(buffer, m->pData + m->offset, (size_t)toread);
    m->offset += toread;
    return toread;
}

/* write to memory */
static OPJ_SIZE_T mem_write(void *buffer, OPJ_SIZE_T nb_bytes, void * p_user_data) {
    opj_memory_stream* m = (opj_memory_stream*) p_user_data;
    if (!m || m->offset >= m->dataSize) return (OPJ_SIZE_T)-1;
    OPJ_SIZE_T towrite = nb_bytes;
    if (towrite > (m->dataSize - m->offset)) towrite = m->dataSize - m->offset;
    memcpy(m->pData + m->offset, buffer, (size_t)towrite);
    m->offset += towrite;
    return towrite;
}

/* skip/seek helpers */
static OPJ_OFF_T mem_skip(OPJ_OFF_T nb_bytes, void * p_user_data) {
    opj_memory_stream* m = (opj_memory_stream*) p_user_data;
    if (!m || nb_bytes < 0) return (OPJ_OFF_T)-1;
    OPJ_SIZE_T toskip = (OPJ_SIZE_T) nb_bytes;
    if (toskip > m->dataSize - m->offset) toskip = m->dataSize - m->offset;
    m->offset += toskip;
    return (OPJ_OFF_T)toskip;
}

static OPJ_BOOL mem_seek(OPJ_OFF_T nb_bytes, void * p_user_data) {
    opj_memory_stream* m = (opj_memory_stream*) p_user_data;
    if (!m || nb_bytes < 0) return OPJ_FALSE;
    if ((OPJ_SIZE_T)nb_bytes > m->dataSize) return OPJ_FALSE;
    m->offset = (OPJ_SIZE_T) nb_bytes;
    return OPJ_TRUE;
}

static void mem_do_nothing(void * p_user_data) { (void)p_user_data; }

/* create a memory-backed opj_stream */
static opj_stream_t* create_memory_stream(opj_memory_stream* mstream, OPJ_BOOL is_read) {
    /* second arg = default buffer size for internal IO ops (e.g. 1KB) */
    opj_stream_t* stream = opj_stream_create(1024, is_read ? OPJ_TRUE : OPJ_FALSE);
    if (!stream) return NULL;

    if (is_read) {
        opj_stream_set_read_function(stream, mem_read);
    } else {
        opj_stream_set_write_function(stream, mem_write);
    }
    opj_stream_set_skip_function(stream, mem_skip);
    opj_stream_set_seek_function(stream, mem_seek);
    opj_stream_set_user_data(stream, mstream, mem_do_nothing);
    opj_stream_set_user_data_length(stream, mstream->dataSize);
    return stream;
}
/* silence OpenJPEG messages (avoid printing in fuzz runs) */
static void silent_msg(const char *msg, void *client_data) { (void)msg; (void)client_data; }

/* Try to decode input as JPEG2000 (J2K or JP2). Returns 1 if decode succeeded, 0 otherwise */
static int try_decode(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;

    opj_memory_stream mstream;
    mstream.pData = (OPJ_BYTE*)data;
    mstream.dataSize = size;
    mstream.offset = 0;

    opj_stream_t *stream = create_memory_stream(&mstream, OPJ_TRUE);
    if (!stream) return 0;

    /* Try both J2K and JP2 codecs (common entry points) */
    opj_codec_t *codec = NULL;
    opj_image_t *image = NULL;
    opj_dparameters_t dparams;
    opj_set_default_decoder_parameters(&dparams);

    /* Try J2K first */
    codec = opj_create_decompress(OPJ_CODEC_J2K);
    if (!codec) { opj_stream_destroy(stream); return 0; }

    opj_set_info_handler(codec, silent_msg, NULL);
    opj_set_warning_handler(codec, silent_msg, NULL);
    opj_set_error_handler(codec, silent_msg, NULL);

    if (!opj_setup_decoder(codec, &dparams)) {
        opj_destroy_codec(codec);
        opj_stream_destroy(stream);
        return 0;
    }

    /* read header */
    mstream.offset = 0;
    if (!opj_read_header(stream, codec, &image)) {
        /* try JP2 */
        opj_destroy_codec(codec);
        codec = opj_create_decompress(OPJ_CODEC_JP2);
        if (!codec) { opj_stream_destroy(stream); return 0; }
        opj_set_info_handler(codec, silent_msg, NULL);
        opj_set_warning_handler(codec, silent_msg, NULL);
        opj_set_error_handler(codec, silent_msg, NULL);
        if (!opj_setup_decoder(codec, &dparams)) {
            opj_destroy_codec(codec);
            opj_stream_destroy(stream);
            return 0;
        }
        mstream.offset = 0;
        if (!opj_read_header(stream, codec, &image)) {
            opj_destroy_codec(codec);
            opj_stream_destroy(stream);
            return 0;
        }
    }

    /* decode */
    int ok = 0;
    if (opj_decode(codec, stream, image)) {
        /* Finish sequence */
        if (opj_end_decompress(codec, stream)) {
            ok = 1;
        }
    }

    if (image) opj_image_destroy(image);
    if (codec) opj_destroy_codec(codec);
    if (stream) opj_stream_destroy(stream);
    return ok;
}

/* Simple encode: create a tiny image from input bytes and compress to memory buffer */
static int try_encode_then_decode_roundtrip(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;

    /* Make a small image: width/height from input (bounded) */
    unsigned w = 1 + (data[0] % 64);
    unsigned h = 1 + (data[1 % size] % 64);
    unsigned numcomps = 1; /* grayscale for simplicity */

    opj_image_cmptparm_t cmptparm;
    cmptparm.dx = 1; cmptparm.dy = 1;
    cmptparm.w = w; cmptparm.h = h;
    cmptparm.sgnd = 0;
    cmptparm.prec = 8; /* 8-bit pixels */

    opj_image_t *image = opj_image_create(numcomps, &cmptparm, OPJ_CLRSPC_GRAY);
    if (!image) return 0;

    /* Fill image data using input bytes (wrap if necessary) */
    OPJ_INT32 *buff = image->comps[0].data;
    size_t needed = (size_t)w * h;
    for (size_t i = 0; i < needed; ++i) {
        buff[i] = (OPJ_INT32) data[i % size];
    }

    /* set image parameters */
    image->x0 = 0; image->y0 = 0;
    image->x1 = w; image->y1 = h;

    /* encoder */
    opj_codec_t *cinfo = opj_create_compress(OPJ_CODEC_J2K);
    if (!cinfo) { opj_image_destroy(image); return 0; }

    opj_cparameters_t cparams;
    opj_set_default_encoder_parameters(&cparams);
    cparams.tcp_numlayers = 1;
    cparams.cp_disto_alloc = 1;
    cparams.tcp_rates[0] = 0; /* lossless-ish / default */
    cparams.irreversible = 0;

    opj_set_info_handler(cinfo, silent_msg, NULL);
    opj_set_warning_handler(cinfo, silent_msg, NULL);
    opj_set_error_handler(cinfo, silent_msg, NULL);

    if (!opj_setup_encoder(cinfo, &cparams, image)) {
        opj_destroy_codec(cinfo);
        opj_image_destroy(image);
        return 0;
    }

    /* prepare output memory buffer for encoded stream */
    size_t outbuf_size = 1024 + w * h * 2; /* rough cap */
    OPJ_BYTE *outbuf = (OPJ_BYTE*) malloc(outbuf_size);
    if (!outbuf) {
        opj_destroy_codec(cinfo);
        opj_image_destroy(image);
        return 0;
    }
    opj_memory_stream outstream_mem;
    outstream_mem.pData = outbuf;
    outstream_mem.dataSize = outbuf_size;
    outstream_mem.offset = 0;

    opj_stream_t *outstream = create_memory_stream(&outstream_mem, OPJ_FALSE);
    if (!outstream) {
        free(outbuf);
        opj_destroy_codec(cinfo);
        opj_image_destroy(image);
        return 0;
    }

    int ok = 0;
    if (opj_start_compress(cinfo, image, outstream)) {
        if (opj_encode(cinfo, outstream)) {
            if (opj_end_compress(cinfo, outstream)) {
                /* successful encode, try to decode the produced bytes */
                size_t produced = outstream_mem.offset;
                if (produced > 0) {
                    ok = try_decode(outbuf, produced);
                }
            }
        }
    }

    /* cleanup */
    opj_stream_destroy(outstream);
    free(outbuf);
    opj_destroy_codec(cinfo);
    opj_image_destroy(image);
    return ok;
}

/* libFuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Minimal guard against zero-length */
    if (!data || size == 0) return 0;

    /* Make OpenJPEG quiet for fuzz runs */

    /* 1) Try decode input as-is (J2K/JP2) */
    (void) try_decode(data, size);

    /* 2) Try encode->decode roundtrip built from input */
    (void) try_encode_then_decode_roundtrip(data, size);

    /* done */
    return 0;
}
