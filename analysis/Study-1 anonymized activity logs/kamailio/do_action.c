// fuzz_do_action_improved.c
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* project headers you used before */
#include "./core/route_struct.h"
#include "./core/parser/msg_parser.h"
#include "./core/action.h"
#include "./core/fmsg.h"
#include "./core/mem/pkg.h"

/* safe max sizes */
#define MAX_STR_COPY 256
#define MAX_PAYLOAD_COPY 1024

/* pick an actionable subset of action types we know how to populate */
static const enum action_type allowed_actions[] = {
    DROP_T,
    LOG_T,
    APPEND_BRANCH_T,
    REMOVE_BRANCH_T,
    CLEAR_BRANCHES_T,
    LEN_GT_T,
    SETFLAG_T,
    RESETFLAG_T,
    ISFLAGSET_T,
    REVERT_URI_T,
    SET_URI_T,
    ASSIGN_T,
    ADD_T,
    CFG_SELECT_T,
    CFG_RESET_T
};

/* helpers to parse values from fuzz input */
static unsigned long pull_u32(const uint8_t *data, size_t size, size_t *off, size_t *rem, unsigned long def) {
    if (!off || !rem) return def;
    if (*rem >= 4) {
        if (*off + 4 > size) { *off = size; *rem = 0; return def; }
        unsigned long v = (unsigned long)data[*off] | ((unsigned long)data[*off + 1] << 8) |
            ((unsigned long)data[*off + 2] << 16) | ((unsigned long)data[*off + 3] << 24);
        *off += 4;
        *rem = (size > *off) ? size - *off : 0;
        return v;
    } else if (*rem >= 1) {
        unsigned long v = data[*off];
        *off += 1;
        *rem = (size > *off) ? size - *off : 0;
        return v;
    }
    return def;
}

static str pull_str_heap(const uint8_t *data, size_t size, size_t *off, size_t *rem) {
    str s;
    s.s = NULL; s.len = 0;
    if (!off || !rem || *rem == 0) return s;
    size_t take = *rem;
    if (take > 64) take = 64;
    if (*off + take > size) take = (size > *off) ? (size - *off) : 0;
    if (take == 0) return s;
    if (take > MAX_STR_COPY) take = MAX_STR_COPY;
    char *buf = (char *)pkg_malloc(take + 1);
    if (!buf) return s;
    memcpy(buf, data + *off, take);
    buf[take] = '\0';
    s.s = buf;
    s.len = (int)take;
    *off += take;
    *rem = (size > *off) ? (size - *off) : 0;
    return s;
}

/* free str created by pull_str_heap */
static void free_str_heap(str *s) {
    if (!s) return;
    if (s->s) pkg_free(s->s);
    s->s = NULL;
    s->len = 0;
}

/* attempt to get a fake sip_msg. Use project's faked_msg_next() if available;
   otherwise create a minimal local sip_msg via malloc. */
extern struct sip_msg *faked_msg_next(void); /* declared in your test helpers / fmsg.h */
static struct sip_msg *get_faked_msg(void) {
    /* prefer project's helper when available */
    struct sip_msg *m = NULL;
    /* faked_msg_next might be available from your test support; try it */
    m = faked_msg_next();
    if (m) return m;
    /* fallback: minimal allocation (best-effort) */
    m = (struct sip_msg *)pkg_malloc(sizeof(struct sip_msg));
    if (!m) return NULL;
    memset(m, 0, sizeof(*m));
    return m;
}

/* cleanup fallback message: if faked_msg_next returned a persistent msg we should not free it.
   But we cannot reliably detect that here — if your test environment uses faked_msg_next,
   it typically returns a heap object intended to be reused. To avoid double-free risk, prefer
   to use the project's faked_msg_next. If unavailable, get_faked_msg allocated it and we free it. */
static void maybe_free_faked_msg(struct sip_msg *m) {
    /* best-effort: if pointer is NULL do nothing; otherwise free */
    if (!m) return;
    /* If your test helper provides faked_msg_next, it may return a global; adjust as needed. */
    pkg_free(m);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 2) return 0;

    size_t action_count = sizeof(allowed_actions) / sizeof(allowed_actions[0]);

    /* pick action using first byte */
    enum action_type chosen = allowed_actions[data[0] % action_count];

    /* prepare message and action */
    struct sip_msg *msg = faked_msg_next();
    if (!msg) return 0;

    struct action act;
    memset(&act, 0, sizeof(act));

    /* default: action type */
    act.type = chosen;

    /* prepare run context */
    struct run_act_ctx h;
    memset(&h, 0, sizeof(h));
    init_run_actions_ctx(&h); /* call into project helper (if present) */

    /* use remaining bytes */
    size_t off = 1;
    size_t rem = (size > off) ? (size - off) : 0;

    /* set msg len (use two bytes if available) */
    if (rem >= 2) {
        msg->len = (int)((data[off] << 8) | data[off + 1]);
        off += 2;
        rem = (size > off) ? (size - off) : 0;
    } else {
        msg->len = (int)rem;
    }

    /* For some actions we pre-populate msg->new_uri to test revert path */
    msg->new_uri.s = NULL;
    msg->new_uri.len = 0;

    /* Fill action parameters according to the chosen action */
    switch (chosen) {
    case DROP_T:
        /* supply a small numeric code in val[0] and flags in val[1] */
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) % 5;
        act.val[1].type = NUMBER_ST;
        act.val[1].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 0xff;
        break;

    case LOG_T:
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 0xff;
        /* message string */
        {
            str s = pull_str_heap(data, size, &off, &rem);
            if (s.len == 0) {
                act.val[1].type = STRING_ST;
                act.val[1].u.string = strdup("fuzzlog");
            } else {
                act.val[1].type = STRING_ST;
                act.val[1].u.string = s.s; /* take ownership */
            }
        }
        break;

    case APPEND_BRANCH_T:
        /* branch name as STR_ST and number param in val[1] */
        {
            str s = pull_str_heap(data, size, &off, &rem);
            act.val[0].type = STR_ST;
            act.val[0].u.str = s;
            act.val[1].type = NUMBER_ST;
            act.val[1].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 0xff;
        }
        break;

    case REMOVE_BRANCH_T:
        /* optional index or no param */
        if (rem >= 1 && (data[off] & 1)) {
            act.val[0].type = NUMBER_ST;
            act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 0xff;
        } else {
            act.val[0].type = NOSUBTYPE;
        }
        break;

    case CLEAR_BRANCHES_T:
        /* no params */
        break;

    case LEN_GT_T:
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 0x3ff;
        break;

    case SETFLAG_T:
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 31;
        break;

    case RESETFLAG_T:
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 31;
        break;

    case ISFLAGSET_T:
        act.val[0].type = NUMBER_ST;
        act.val[0].u.number = (long)pull_u32(data, size, &off, &rem, 0) & 31;
        /* set some flags to make this interesting */
        msg->flags = 0xA5A5A5A5u;
        break;

    case REVERT_URI_T:
        /* make msg->new_uri non-null so revert frees it */
        {
            const char *preset = "sip:old@fuzz";
            char *p = (char *)pkg_malloc(strlen(preset) + 1);
            if (p) {
                strcpy(p, preset);
                msg->new_uri.s = p;
                msg->new_uri.len = (int)strlen(p);
            }
        }
        break;

    case SET_URI_T:
        {
            /* set a new URI from fuzz data */
            str s = pull_str_heap(data, size, &off, &rem);
            if (s.len == 0) {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = strdup("sip:user@fuzz");
            } else {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = s.s; /* take ownership */
            }
        }
        break;

    case ASSIGN_T:
        /* assign: val[0] key (string), val[1] value (string or number) */
        {
            str key = pull_str_heap(data, size, &off, &rem);
            if (key.len == 0) {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = strdup("var");
            } else {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = key.s;
            }
            /* value: sometimes number, sometimes string */
            if (rem >= 1 && (data[off] & 1)) {
                act.val[1].type = NUMBER_ST;
                act.val[1].u.number = (long)pull_u32(data, size, &off, &rem, 0);
            } else {
                str v = pull_str_heap(data, size, &off, &rem);
                if (v.len == 0) {
                    act.val[1].type = STRING_ST;
                    act.val[1].u.string = strdup("1");
                } else {
                    act.val[1].type = STRING_ST;
                    act.val[1].u.string = v.s;
                }
            }
        }
        break;

    case ADD_T:
        act.val[0].type = STRING_ST;
        {
            str key = pull_str_heap(data, size, &off, &rem);
            if (key.len == 0) {
                act.val[0].u.string = strdup("cnt");
            } else {
                act.val[0].u.string = key.s;
            }
        }
        act.val[1].type = NUMBER_ST;
        act.val[1].u.number = (long)pull_u32(data, size, &off, &rem, 1) & 0xff;
        break;

    case CFG_SELECT_T:
        /* CFG_SELECT: val[0] group string, val[1] number */
        {
            str g = pull_str_heap(data, size, &off, &rem);
            if (g.len == 0) {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = strdup("default");
            } else {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = g.s;
            }
            act.val[1].type = NUMBER_ST;
            act.val[1].u.number = (long)pull_u32(data, size, &off, &rem, 0);
        }
        break;

    case CFG_RESET_T:
        {
            str g = pull_str_heap(data, size, &off, &rem);
            if (g.len == 0) {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = strdup("default");
            } else {
                act.val[0].type = STRING_ST;
                act.val[0].u.string = g.s;
            }
        }
        break;

    default:
        /* unknown action - no params */
        break;
    }

    /* call do_action (project function) */
    do_action(&h, &act, msg);

    /* cleanup: free strings / str members in action */
    // for (int i = 0; i < MAX_ACTION_VALS; ++i) {
    //     int vtype = act.val[i].type;
    //     if (vtype == STRING_ST && act.val[i].u.string) {
    //         free(act.val[i].u.string);
    //         act.val[i].u.string = NULL;
    //     } else if (vtype == STR_ST) {
    //         /* free underlying string */
    //         if (act.val[i].u.str.s) pkg_free(act.val[i].u.str.s);
    //         act.val[i].u.str.s = NULL;
    //         act.val[i].u.str.len = 0;
    //     } else if (vtype == RVE_ST && act.val[i].u.data) {
    //         /* if we allocated any simple rve-like data, free it (we didn't here) */
    //         pkg_free(act.val[i].u.data);
    //         act.val[i].u.data = NULL;
    //     }
    // }

    /* cleanup msg new_uri if we created it for revert */
    // if (msg->new_uri.s) {
    //     pkg_free(msg->new_uri.s);
    //     msg->new_uri.s = NULL;
    //     msg->new_uri.len = 0;
    // }

    /* if we allocated a fallback sip_msg, free it; if faked_msg_next returned
       a shared object you may need to avoid freeing. Adjust get_faked_msg/maybe_free_faked_msg
       to match your environment. */
    // maybe_free_faked_msg(msg);

    return 0;
}
