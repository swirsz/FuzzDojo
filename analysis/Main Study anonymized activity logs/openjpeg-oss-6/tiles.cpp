#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "openjpeg.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len);

typedef struct {
    const uint8_t* pabyData;
    size_t         nCurPos;
    size_t         nLength;
} MemFile;


static void ErrorCallback(const char * msg, void *)
{
    (void)msg;
    //fprintf(stderr, "%s\n", msg);
}


static void WarningCallback(const char *, void *)
{
}

static void InfoCallback(const char *, void *)
{
}

static OPJ_SIZE_T ReadCallback(void* pBuffer, OPJ_SIZE_T nBytes,
                               void *pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    //printf("want to read %d bytes at %d\n", (int)memFile->nCurPos, (int)nBytes);
    if (memFile->nCurPos >= memFile->nLength) {
        return -1;
    }
    if (memFile->nCurPos + nBytes >= memFile->nLength) {
        size_t nToRead = memFile->nLength - memFile->nCurPos;
        memcpy(pBuffer, memFile->pabyData + memFile->nCurPos, nToRead);
        memFile->nCurPos = memFile->nLength;
        return nToRead;
    }
    if (nBytes == 0) {
        return -1;
    }
    memcpy(pBuffer, memFile->pabyData + memFile->nCurPos, nBytes);
    memFile->nCurPos += nBytes;
    return nBytes;
}

static OPJ_BOOL SeekCallback(OPJ_OFF_T nBytes, void * pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    //printf("seek to %d\n", (int)nBytes);
    memFile->nCurPos = nBytes;
    return OPJ_TRUE;
}

static OPJ_OFF_T SkipCallback(OPJ_OFF_T nBytes, void * pUserData)
{
    MemFile* memFile = (MemFile*)pUserData;
    memFile->nCurPos += nBytes;
    return nBytes;
}


int LLVMFuzzerInitialize(int* /*argc*/, char*** argv)
{
    return 0;
}

static const unsigned char jpc_header[] = {0xff, 0x4f};
static const unsigned char jp2_box_jp[] = {0x6a, 0x50, 0x20, 0x20}; /* 'jP  ' */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	const char *version = opj_version();

	opj_image_t *new_image = NULL;
	opj_image_cmptparm_t param_image_write;
	param_image_write.x0 = 0;
    param_image_write.y0 = 0;
    param_image_write.dx = 0;
    param_image_write.dy = 0;
    param_image_write.h = 10;//image->comps[num_comp_select].h;
    param_image_write.w = 10;//image->comps[num_comp_select].w;
    param_image_write.prec = 10;//image->comps[num_comp_select].prec;
    param_image_write.sgnd = 10;//image->comps[num_comp_select].sgnd;
	new_image = opj_image_create((OPJ_UINT32)1, &param_image_write, OPJ_CLRSPC_UNSPECIFIED);
	//memcpy(new_image->comps->data, data, param_image_write.h * param_image_write.w * sizeof(int));

	if (new_image)
    	opj_image_destroy(new_image);

	/*
    opj_stream_t * l_stream;
    OPJ_UINT32 l_nb_tiles_width, l_nb_tiles_height, l_nb_tiles;
    OPJ_UINT32 l_data_size;
	*/

	// add tile encoding
	opj_cparameters_t l_param;
	opj_set_default_encoder_parameters(&l_param);

	if (data[0])
		opj_codec_t *l_codec = opj_create_compress(OPJ_CODEC_JP2);
	else
		opj_codec_t *l_codec = opj_create_compress(OPJ_CODEC_J2K);
    
	opj_image_cmptparm_t l_params [4];
	OPJ_UINT32 num_comps = 3;

	int image_width = 200;
    int image_height = 200;
	OPJ_UINT32 offsetx = 0;
    OPJ_UINT32 offsety = 0;
	int comp_prec= 8;

	    /* image definition */
    opj_image_cmptparm_t *l_current_param_ptr = l_params;
    for (int i = 0; i < num_comps; ++i) {
        /*l_current_param_ptr->bpp = COMP_PREC;*/
        l_current_param_ptr->dx = 1;
        l_current_param_ptr->dy = 1;

        l_current_param_ptr->h = (OPJ_UINT32)image_height;
        l_current_param_ptr->w = (OPJ_UINT32)image_width;

        l_current_param_ptr->sgnd = 0;
        l_current_param_ptr->prec = (OPJ_UINT32)comp_prec;

        l_current_param_ptr->x0 = offsetx;
        l_current_param_ptr->y0 = offsety;

        ++l_current_param_ptr;
    }

    opj_image_t * l_image = opj_image_tile_create(num_comps, l_params, OPJ_CLRSPC_SRGB);


    return 0;
}
