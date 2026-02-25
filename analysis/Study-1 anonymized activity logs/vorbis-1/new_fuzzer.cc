#include <stdint.h>
#include <string.h>
#include <vorbis/vorbisfile.h>
#include <cmath>
struct vorbis_data {
  const uint8_t *data;
  const uint8_t *current;
  size_t size;
};

static size_t read_func(void *ptr, size_t size, size_t nmemb, void *datasource) {
    struct vorbis_data *vd = (struct vorbis_data *)datasource;
    size_t want_bytes = size * nmemb;
    size_t avail_bytes = (size_t)(vd->data + vd->size - vd->current);
    size_t actual_bytes = (want_bytes < avail_bytes) ? want_bytes : avail_bytes;
    
    if (actual_bytes > 0) {
        memcpy(ptr, vd->current, actual_bytes);
        vd->current += actual_bytes;
    }
    
    // Return number of complete elements read
    return actual_bytes / size;
}

static int seek_func(void *datasource, ogg_int64_t offset, int whence) {
    struct vorbis_data *vd = (struct vorbis_data *)datasource;
    const uint8_t *newpos = NULL;
    
    switch (whence) {
        case SEEK_SET: newpos = vd->data + offset; break;
        case SEEK_CUR: newpos = vd->current + offset; break;
        case SEEK_END: newpos = vd->data + vd->size + offset; break;
        default: return -1;
    }
    
    if (newpos < vd->data || newpos > vd->data + vd->size) {
        return -1;
    }
    
    vd->current = newpos;
    return 0;  // Success
}

static long tell_func(void *datasource) {
    struct vorbis_data *vd = (struct vorbis_data *)datasource;
    return (long)(vd->current - vd->data);
}

static int close_func(void *datasource) {
    return 0;  // No-op for memory buffer
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct vorbis_data vd = { Data, Data, Size };
  OggVorbis_File vf;
  ov_callbacks cbs;
  cbs.read_func  = read_func;
  cbs.seek_func  = seek_func;
  cbs.tell_func  = tell_func;
  cbs.close_func = close_func;

  if (ov_open_callbacks(&vd, &vf, NULL, 0, cbs) < 0) return 0;

  if (ov_seekable(&vf)) {
    double total = ov_time_total(&vf, -1);
    if (total > 0.0) {
      // Derive a deterministic time from input bytes.
      uint64_t v = 0;
      size_t n = Size < 8 ? Size : 8;
      memcpy(&v, Data + (Size - n), n);
      double t = fmod((double)v, total);
      (void)ov_time_seek_page_lap(&vf, t);
      // Optional: exercise a read after seeking
      // char buf[4096]; int bitstream = 0; (void)ov_read(&vf, buf, sizeof(buf), 0, 2, 1, &bitstream);
    }
  }

  ov_clear(&vf);
  return 0;
}
