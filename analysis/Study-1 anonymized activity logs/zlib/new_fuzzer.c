/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include "zlib.h"

#define INLEN 0x1000
#define OUTLEN 0x4000
char input_buffer[INLEN];
char compressed_buffer[OUTLEN];
char output_buffer[OUTLEN];

Bytef dict[1 << 15]; 
uInt got = (uInt)sizeof(dict);


void deflate_stuff(){
  z_stream strm;
  memset(&strm, 0, sizeof(strm));

  int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK) {
    fprintf(stderr, "deflateInit2 failed: %d\n", ret);
    return;
  }

  ret = deflateTune(&strm, 8, 16, 32, 128);
  if (ret != Z_OK) {
    fprintf(stderr, "deflateTune failed: %d\n", ret);
    deflateEnd(&strm);
    return;
  }
  
  gz_header wh = {0};
  static Bytef fname[]  = "one-block.bin";
  static Bytef comment[] = "custom gzip header";
  unsigned char extra_bytes[] = { 0x41, 0x42 };
  wh.text = 1;
  wh.time = (uLong)time(NULL);
  wh.os   = 3;            // Unix
  wh.name = fname;
  wh.comment = comment;
  wh.hcrc = 1;
  wh.extra = extra_bytes;
  wh.extra_len = sizeof(extra_bytes);
  ret = deflateSetHeader(&strm, &wh);
  if (ret != Z_OK) { 
    fprintf(stderr, "deflateSetHeader failed: %d\n", ret); deflateEnd(&strm);
    return; 
  }

  deflateBound(&strm, INLEN);

  strm.next_in = (Bytef*)input_buffer;
  strm.avail_in = (uInt)INLEN/2; // feed half input to create pending
  strm.next_out = (Bytef*)compressed_buffer;
  strm.avail_out = (uInt)OUTLEN/2; // small output to create pending

  z_stream strm_copy;
  memset(&strm_copy, 0, sizeof(strm_copy));
  ret = deflateCopy(&strm_copy, &strm);
  if (ret != Z_OK) {
    fprintf(stderr, "deflateCopy failed: %d\n", ret);
    deflateEnd(&strm);
    return;
  }

  ret = deflate(&strm, Z_NO_FLUSH);
  if (ret != Z_STREAM_END && ret != Z_OK) {
    fprintf(stderr, "deflate1 failed: %d\n", ret);
    deflateEnd(&strm); 
    return;
  }

  int used_bits = 0;
  ret = deflateUsed(&strm, &used_bits);
  if (ret != Z_OK) {
    fprintf(stderr, "deflateUsed failed: %d\n", ret);
    deflateEnd(&strm); 
    return;
  }


  unsigned pending = 0; int pbits = 0;
  ret = deflatePending(&strm, &pending, &pbits);
  if (ret != Z_OK) {
    fprintf(stderr, "deflatePending failed: %d\n", ret);
    deflateEnd(&strm);
    return;
  }

  ret = deflatePrime(&strm, 2, 1);
  if (ret != Z_OK) {
    fprintf(stderr, "deflatePrime failed: %d\n", ret);
    deflateEnd(&strm);
    return;
  }

  ret = deflateGetDictionary(&strm, dict, &got);
  if (ret != Z_OK) {
    fprintf(stderr, "deflateGetDictionary failed: %d\n", ret);
    deflateEnd(&strm);
    return;
  }

  deflateParams(&strm, Z_BEST_COMPRESSION, Z_DEFAULT_STRATEGY);
  ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END && ret != Z_OK) {
    fprintf(stderr, "deflate2 failed: %d\n", ret);
    deflateEnd(&strm); 
    deflateEnd(&strm_copy);
    return;
  }

  memset(compressed_buffer, 0, sizeof(compressed_buffer));
  strm_copy.next_in = (Bytef*)input_buffer;
  strm_copy.avail_in = (uInt)INLEN;
  strm_copy.next_out = (Bytef*)compressed_buffer;
  strm_copy.avail_out = (uInt)OUTLEN;

  ret = deflate(&strm_copy, Z_FINISH);
  if (ret != Z_STREAM_END && ret != Z_OK) {
    fprintf(stderr, "deflate3 failed: %d\n", ret);
    deflateEnd(&strm); 
    deflateEnd(&strm_copy);
    return;
  }

  deflateEnd(&strm_copy);
  deflateEnd(&strm);

}

void inflate_stuff(){
  z_stream strm;
  memset(&strm, 0, sizeof(strm));

  int ret = inflateInit2(&strm, 15 + 32);
  if (ret != Z_OK) {
    fprintf(stderr, "inflateInit2 failed: %d\n", ret);
    return;
  }

  gz_header rh;
  memset(&rh, 0, sizeof(rh));
  unsigned char extra[64], name[64], comm[64];
  rh.extra = extra; rh.extra_max = sizeof(extra);
  rh.name  = name;  rh.name_max  = sizeof(name);
  rh.comment = comm; rh.comm_max = sizeof(comm);
  ret = inflateGetHeader(&strm, &rh);
  if (ret != Z_OK) {
    fprintf(stderr, "inflateGetHeader failed: %d\n", ret);
    inflateEnd(&strm);
    return;
  }

  z_stream strm_copy;
  memset(&strm_copy, 0, sizeof(strm_copy));

  ret = inflateCopy(&strm_copy, &strm);
  if (ret != Z_OK) {
    fprintf(stderr, "inflateCopy failed: %d\n", ret);
    inflateEnd(&strm);
    return;
  }

  ret = inflatePrime(&strm, -1, 0);
  if (ret != Z_OK) {
    fprintf(stderr, "inflatePrime(-1) failed: %d\n", ret);
    inflateEnd(&strm);
    return;
  }

  ret = inflatePrime(&strm_copy, 12, 0);
  if (ret != Z_OK) {
    fprintf(stderr, "inflatePrime(-1) failed: %d\n", ret);
    inflateEnd(&strm);
    return;
  }

  strm.next_in = (Bytef*)compressed_buffer;
  strm.avail_in = (uInt)sizeof(compressed_buffer);
  strm.next_out = (Bytef*)output_buffer;
  strm.avail_out = (uInt)sizeof(output_buffer);

  strm_copy.next_in = (Bytef*)compressed_buffer;
  strm_copy.avail_in = (uInt)sizeof(compressed_buffer);
  strm_copy.next_out = (Bytef*)output_buffer;
  strm_copy.avail_out = (uInt)sizeof(output_buffer);

  (void)inflateValidate(&strm, 0);
  (void)inflateUndermine(&strm, 1);

  int sync_point = inflateSyncPoint(&strm);

  (void)inflate(&strm, Z_SYNC_FLUSH);

  ret = inflateGetDictionary(&strm, dict, &got);
  if (ret != Z_OK) {
    fprintf(stderr, "inflateGetDictionary failed: %d\n", ret);
    inflateEnd(&strm);
    inflateEnd(&strm_copy);
    return;
  }

  long mark = inflateMark(&strm);
  
  ret = inflate(&strm, Z_FINISH);
  ret = inflate(&strm_copy, Z_FINISH);
  
  unsigned long codes_used = inflateCodesUsed(&strm);
  
  inflateEnd(&strm);
  inflateEnd(&strm_copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  if (size < 10 || size > 1024 * 1024)
      return 0;

  memcpy(input_buffer, d, size > INLEN ? INLEN : size);
  deflate_stuff();
  inflate_stuff();
  return 0;
}


/*  
s->gzhead->extra in deflate

*/