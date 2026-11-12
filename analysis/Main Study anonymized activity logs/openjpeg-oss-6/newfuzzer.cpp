#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include "openjpeg.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len);

typedef struct {
    uint8_t*       pabyData;
    size_t         nCurPos;
    size_t         nLength;
} MemFile;

#define PNG_DFMT 17
#define J2K_CFMT 0

static void ErrorCallback(const char * msg, void *)
{
    (void)msg;
}

static void WarningCallback(const char *, void *)
{
}

static void InfoCallback(const char *, void *)
{
}

static OPJ_SIZE_T WriteCallback(void* pBuffer, OPJ_SIZE_T nBytes,
                                void *pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    
    // Check if we need to expand buffer
    if (memFile->nCurPos + nBytes > memFile->nLength) {
        size_t newSize = memFile->nCurPos + nBytes;
        uint8_t* newBuf = (uint8_t*)realloc(memFile->pabyData, newSize);
        if (!newBuf) {
            return (OPJ_SIZE_T)-1;
        }
        memFile->pabyData = newBuf;
        memFile->nLength = newSize;
    }
    
    memcpy(memFile->pabyData + memFile->nCurPos, pBuffer, nBytes);
    memFile->nCurPos += nBytes;
    return nBytes;
}

static OPJ_BOOL SeekCallback(OPJ_OFF_T nBytes, void * pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    memFile->nCurPos = nBytes;
    return OPJ_TRUE;
}

static OPJ_OFF_T SkipCallback(OPJ_OFF_T nBytes, void * pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    memFile->nCurPos += nBytes;
    return nBytes;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
    // Minimum input validation
    if (len < 16) {
        return 0;
    }

    const char * v = opj_version();

    /* encoder */
    OPJ_BOOL bSuccess;

    // CREATE IMAGE
    opj_cparameters_t cparameters;
    opj_set_default_encoder_parameters(&cparameters);
    cparameters.decod_format = PNG_DFMT;
    cparameters.cod_format = J2K_CFMT;

    const OPJ_COLOR_SPACE color_space = OPJ_CLRSPC_SRGB;
    unsigned int numcomps = 4;
    unsigned int image_width = 256;
    unsigned int image_height = 256;
    unsigned int subsampling_dx;
    unsigned int subsampling_dy;
    
    opj_image_cmptparm_t cmptparm[4]; // Fixed: was 6, should match max numcomps
    memset(&cmptparm[0], 0, 4 * sizeof(opj_image_cmptparm_t));
    subsampling_dx = cparameters.subsampling_dx;
    subsampling_dy = cparameters.subsampling_dy;

    for (unsigned int i = 0; i < numcomps; i++) { // changed int to unsigned int
        cmptparm[i].prec = 8;
        cmptparm[i].sgnd = 0;
        cmptparm[i].dx = (OPJ_UINT32)subsampling_dx;
        cmptparm[i].dy = (OPJ_UINT32)subsampling_dy;
        cmptparm[i].w = image_width;
        cmptparm[i].h = image_height;
    }

    opj_image_t *image = opj_image_create((OPJ_UINT32)numcomps, &cmptparm[0], color_space);
    if (!image) {
        return 0;
    }
   
    // Initialize image data with fuzz input
    size_t dataIdx = 0;
    for (unsigned int i = 0; i < image_width * image_height && dataIdx < len; i++) {
        for (unsigned int compno = 0; compno < numcomps && dataIdx < len; compno++) {
            image->comps[compno].data[i] = data[dataIdx++];
        }
    }

    // CREATE CODEC
    OPJ_CODEC_FORMAT eCodecFormat = OPJ_CODEC_J2K;
    opj_codec_t *l_codec = opj_create_compress(eCodecFormat);
    if (!l_codec) {
        opj_image_destroy(image);
        return 0;
    }
    
    opj_set_info_handler(l_codec, InfoCallback, NULL);
    opj_set_warning_handler(l_codec, WarningCallback, NULL);
    opj_set_error_handler(l_codec, ErrorCallback, NULL);

    // ENCODER
    if (!opj_setup_encoder(l_codec, &cparameters, image))
    {
        opj_destroy_codec(l_codec);
        opj_image_destroy(image);
        return 0;
    }

    // STREAM - Fixed: OPJ_FALSE means output stream for writing
    opj_stream_t *l_stream = opj_stream_create(1024, OPJ_FALSE);
    if (!l_stream)
    {
        opj_destroy_codec(l_codec);
        opj_image_destroy(image);
        return 0;
    }
    
    // Allocate output buffer
    MemFile memFile;
    memFile.pabyData = (uint8_t*)malloc(1024);
    if (!memFile.pabyData) {
        opj_stream_destroy(l_stream);
        opj_destroy_codec(l_codec);
        opj_image_destroy(image);
        return 0;
    }
    memFile.nLength = 1024;
    memFile.nCurPos = 0;
    
    opj_stream_set_write_function(l_stream, WriteCallback); // use write, not read
    opj_stream_set_seek_function(l_stream, SeekCallback);
    opj_stream_set_skip_function(l_stream, SkipCallback);
    opj_stream_set_user_data(l_stream, &memFile, NULL);

    // COMPRESS
    bSuccess = opj_start_compress(l_codec, image, l_stream);
    if (bSuccess)
    {
        bSuccess = opj_encode(l_codec, l_stream);
        bSuccess = opj_end_compress(l_codec, l_stream);
    }

    // Cleanup
    free(memFile.pabyData);
    opj_stream_destroy(l_stream);
    opj_destroy_codec(l_codec);
    opj_image_destroy(image);

    return 0;
}