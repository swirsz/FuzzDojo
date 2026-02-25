// fuzz_sr_kemi_match_method_id.c
// Fuzz harness for sr_kemi_core_match_method_id from kemi.c

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* include the project's headers (adjust paths if necessary) */
#include "./core/kemi.h"
#include "./core/str.h"
#include "./core/kemi.c"
#include "./core/msg_translator.h"
#include "./core/parser/msg_parser.h"
#include "./core/fmsg.h"

/*
 * Helper: create a heap-backed str from bytes.
 * We copy at most MAX_LEN bytes to avoid huge allocations.
 */
#define MAX_INPUT_PART 256

char *build_res_buf_from_sip_req(unsigned int code, str *text, str *new_tag, struct sip_msg *msg, unsigned int *returned_len, struct bookmark *bmark);
char *generate_res_buf_from_sip_res(struct sip_msg *msg, unsigned int *returned_len, unsigned int mode);

static str make_str_from_blob(const uint8_t *data, size_t len) {
    str s;
    size_t use = len;
    if (use > MAX_INPUT_PART) use = MAX_INPUT_PART;
    if (use == 0) {
        s.s = NULL;
        s.len = 0;
        return s;
    }
    char *buf = malloc(use);
    if (!buf) {
        s.s = NULL;
        s.len = 0;
        return s;
    }
    memcpy(buf, data, use);
    s.s = buf;
    s.len = (int)use;
    return s;
}

/* free a str created by make_str_from_blob */
// static void free_str_blob(str *s) {
//     if (!s) return;
//     if (s->s) free((void *)s->s);
//     s->s = NULL;
//     s->len = 0;
// }

/*
 * Input layout (flexible / tolerant):
 *  - first 4 bytes (if present) -> mid (int)
 *  - remaining bytes split in half: left -> rmethod, right -> vmethod
 *
 * If input is too small, function will still run (uses empty strings).
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) return 0;

    sip_msg_t orig_inv = { };
    orig_inv.buf = (char*)data;
    orig_inv.len = size;
    orig_inv.first_line.type = SIP_REQUEST;
    orig_inv.first_line.u.request.method_value = 0;
    orig_inv.rcv.proto = PROTO_TCP;
    orig_inv.dst_uri.s = (char*)data;
    orig_inv.dst_uri.len = size;
    str txt;
    txt.s = "hello\0";
    txt.len = 7;
    str level;
    level.s = NULL;
    level.len = 0;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "dbg\0";
    level.len = 5;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "info\0";
    level.len = 6;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "notice\0";
    level.len = 8;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "warn\0";
    level.len = 6;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "err\0";
    level.len = 5;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "crit\0";
    level.len = 6;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    level.s = "rand\0";
    level.len = 6;
    sr_kemi_core_log(&orig_inv, &level, &txt);
    sr_kemi_core_set_drop(&orig_inv);
    sr_kemi_core_is_myself(&orig_inv, &txt);
    sr_kemi_core_is_myself_ruri(&orig_inv);
    sr_kemi_core_is_myself_duri(&orig_inv);
    sr_kemi_core_is_myself_nhuri(&orig_inv);
    sr_kemi_core_is_myself_furi(&orig_inv);
    sr_kemi_core_is_myself_turi(&orig_inv);
    sr_kemi_core_is_myself_suri(&orig_inv);
    sr_kemi_core_is_myself_srcip(&orig_inv);
    sr_kemi_core_setflag(&orig_inv, 0);
    sr_kemi_core_resetflag(&orig_inv, 0);
    sr_kemi_core_isflagset(&orig_inv, 0);
    sr_kemi_core_setbiflag(&orig_inv, 0, 0);
    sr_kemi_core_resetbiflag(&orig_inv, 0, 0);
    sr_kemi_core_isbiflagset(&orig_inv, 0, 0);
    sr_kemi_core_setbflag(&orig_inv, 0);
    sr_kemi_core_setsflag(&orig_inv, 0);
    sr_kemi_core_seturi(&orig_inv, &txt);
    sr_kemi_core_setuser(&orig_inv, &txt);
    sr_kemi_core_sethost(&orig_inv, &txt);

    str vmethod;
    vmethod.s = "iabcmrepsnofgukdtvz";
    vmethod.len = 20;
    sr_kemi_core_is_method(&orig_inv, &vmethod);
    sr_kemi_core_is_method_in(&orig_inv, &vmethod);

    sr_kemi_core_is_method_type(&orig_inv, 0);
    sr_kemi_core_is_proto_tcpx(&orig_inv);
    sr_kemi_core_is_proto_wsx(&orig_inv);
    sr_kemi_core_is_proto(&orig_inv, &vmethod);

    str message;
    message.s = (char*)data;
    message.len = size;

    sr_kemi_core_set_advertised_address(&orig_inv, &message);
    sr_kemi_core_set_advertised_port(&orig_inv, &message);
    sr_kemi_core_to_proto_helper(&orig_inv);
    sr_kemi_core_to_af_helper(&orig_inv);
    sr_kemi_core_to_af_ipv4(&orig_inv);
    sr_kemi_hdr_append(&orig_inv, &message);
    sr_kemi_hdr_append_after(&orig_inv, &message, &vmethod);
    sr_kemi_hdr_is_present(&orig_inv, &vmethod);
    sr_kemi_hdr_remove(&orig_inv, &vmethod);
    sr_kemi_hdr_insert(&orig_inv, &message);
    sr_kemi_hdr_insert_before(&orig_inv, &message, &vmethod);

    sr_kemi_hdr_get_mode(&orig_inv, &vmethod, (int)data[0], (int)data[1]);
    sr_kemi_hdr_match_content(&orig_inv, &vmethod, &txt, &vmethod, &txt);
    sr_kemi_pv_get_mode(&orig_inv, &vmethod, (int)data[0]);
    sr_kemi_pv_geti(&orig_inv, &vmethod);
    sr_kemi_pv_getl(&orig_inv, &vmethod);
    sr_kemi_pv_seti(&orig_inv, &vmethod, (int)data[0]);
    sr_kemi_pv_sets(&orig_inv, &message, &vmethod);
    sr_kemi_cbname_lookup_name(&message);
    sr_kemi_cbname_lookup_idx(0);

    reset_uri(&orig_inv);
    msg_ldata_reset(&orig_inv);
    unsigned int returned_len = 0;
    // build_res_buf_from_sip_res(&orig_inv, &returned_len);
    build_res_buf_from_sip_req(0, &message, &vmethod, &orig_inv, &returned_len, NULL);

    /* faked_msg_next might be available from your test support; try it */
    faked_msg_init();
    // struct sip_msg *m = faked_msg_next();
    // generate_res_buf_from_sip_res(FAKED_REPLY, &returned_len, 0);
    fix_all_socket_lists();

    uint32_t mid = 0;
    size_t offset = 0;
    if (size >= 4) {
        mid = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
              ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        offset = 4;
    }

    size_t rem = (size > offset) ? (size - offset) : 0;
    size_t rlen = rem / 2;
    size_t vlen = rem - rlen;

    const uint8_t *rptr = data + offset;
    const uint8_t *vptr = data + offset + rlen;

    /* Create str objects (heap allocated buffers) */
    str rmethod = make_str_from_blob(rptr, rlen);
    str vmethod2 = make_str_from_blob(vptr, vlen);

    /* if we created zero-length strings ensure s pointers are non-NULL for
       functions that expect non-NULL; the real code checks vmethod2->s != NULL. */
    if (rmethod.len == 0 && rmethod.s == NULL) {
        /* supply a valid empty string pointer */
        rmethod.s = "";
    }
    if (vmethod2.len == 0 && vmethod2.s == NULL) {
        vmethod2.s = "";
    }

    /* Call the function under test. It returns SR_KEMI_TRUE / FALSE (1/0). */
    (void) sr_kemi_core_match_method_id(&rmethod, &vmethod2, (int)mid);

    /* cleanup heap buffers allocated by make_str_from_blob */
    // free_str_blob(&rmethod);
    // free_str_blob(&vmethod2);

    // free_sip_msg(&orig_inv);
    return 0;
}
