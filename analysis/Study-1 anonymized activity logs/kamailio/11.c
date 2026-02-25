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
// fuzz_fix_actions.c
// #define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

/* include the route structures you uploaded */
#include "./core/route_struct.h"
#include "./core/mem/pkg.h"
#include "./core/ip_addr.h"

/* forward-declare the function under test */
int fix_actions(struct action *a);


/* minimal proxy/list/socket structures just to satisfy types */
struct proxy_l { int dummy; };

/* add_proxy: create a dummy proxy object and return pointer */
struct proxy_l *add_proxy(str *s, long port, int proto) {
    (void)s; (void)port; (void)proto;
    struct proxy_l *p = pkg_malloc(sizeof(*p));
    if (!p) return NULL;
    p->dummy = 1;
    return p;
}

/* DNS / host resolution stubs used by FORCE_SEND_SOCKET_T */
struct hostent *resolvehost(const char *name) {
    (void)name;
    /* return a minimal hostent (allocated once) */
    static struct hostent he;
    static char *aliases[1] = { NULL };
    static char namebuf[32] = "localhost";
    he.h_name = namebuf;
    he.h_aliases = aliases;
    he.h_addrtype = AF_INET;
    he.h_length = 4;
    static char addrbuf[4] = {0,0,0,0};
    static char *addrlist[2] = { (char*)addrbuf, NULL };
    he.h_addr_list = addrlist;
    return &he;
}

/* minimal socket id struct used by FORCE_SEND_SOCKET_T in route.c */
struct addr_list { char *name; struct addr_list *next; };

/* make sure these symbolic constants exist for harness */
#ifndef PROTO_TCP
#define PROTO_TCP 6
#endif

/* -------------------- helpers to build action lists ---------------------- */

/* create a basic action node with zeroed fields */
static struct action *mk_empty_action(enum action_type type) {
    struct action *a = pkg_malloc(sizeof(*a));
    if (!a) return NULL;
    memset(a, 0, sizeof(*a));
    a->type = type;
    a->count = 0;
    a->next = NULL;
    return a;
}

/* create a FORWARD_* action with a string target (a->val[0] = STRING_ST) */
static struct action *mk_forward_string(enum action_type type, const char *s, int port) {
    struct action *a = mk_empty_action(type);
    if (!a) return NULL;
    a->val[0].type = STRING_ST;
    a->val[0].u.string = strdup(s ? s : "127.0.0.1");
    a->val[1].type = NUMBER_ST;
    a->val[1].u.number = port;
    return a;
}

/* create a MODULE0_T-like action (module function with zero params) */
static struct action *mk_module0(const char *name) {
    struct action *a = mk_empty_action(MODULE0_T);
    if (!a) return NULL;
    /* emulate ksr_cmd_export_t pointer in val[0] (route.c looks at cmd->name only in debug) */
    /* keep as NULL to avoid extra complexity - route.c guards for cmd==NULL */
    a->val[1].type = NUMBER_ST;
    a->val[1].u.number = 0; /* zero params -> triggers call_fixup(cmd->fixup,0,0) path if cmd present */
    return a;
}

/* create FORCE_SEND_SOCKET_T action: set val[0].type = SOCKID_ST and point to socket_id */
static struct action *mk_force_send_socket(const char *name, int port, int proto) {
    struct action *a = mk_empty_action(FORCE_SEND_SOCKET_T);
    if (!a) return NULL;
    struct socket_id *sid = pkg_malloc(sizeof(*sid));
    memset(sid, 0, sizeof(*sid));
    struct addr_list *al = pkg_malloc(sizeof(*al));
    al->name = strdup(name ? name : "localhost");
    al->next = NULL;
    sid->addr_lst = al;
    sid->port = port;
    sid->proto = proto;
    a->val[0].type = SOCKID_ST;
    a->val[0].u.data = sid;
    return a;
}

/* mk_cfg_select: t->val[0] STRING_ST, t->val[1] NUMBER_ST */
static struct action *mk_cfg_select(const char *group, long num) {
    struct action *a = mk_empty_action(CFG_SELECT_T);
    if (!a) return NULL;
    a->val[0].type = STRING_ST;
    a->val[0].u.string = strdup(group ? group : "default");
    a->val[1].type = NUMBER_ST;
    a->val[1].u.number = num;
    return a;
}

/* free action list and allocated strings/structs (best-effort) */
static void free_actions(struct action *a) {
    struct action *t = a;
    while (t) {
        for (int i = 0; i < MAX_ACTIONS; i++) {
            if (t->val[i].type == STRING_ST && t->val[i].u.string) {
                free(t->val[i].u.string);
            } else if (t->val[i].type == SOCKID_ST && t->val[i].u.data) {
                struct socket_id *sid = t->val[i].u.data;
                if (sid->addr_lst) free(sid->addr_lst->name), pkg_free(sid->addr_lst);
                pkg_free(sid);
            } else if (t->val[i].type == PROXY_ST && t->val[i].u.data) {
                pkg_free(t->val[i].u.data);
            } else if (t->val[i].type == CFG_GROUP_ST && t->val[i].u.data) {
                pkg_free(t->val[i].u.data);
            }
        }
        struct action *n = t->next;
        pkg_free(t);
        t = n;
    }
}

/* -------------------- libFuzzer entrypoint ------------------------------- */

/* Mode map:
   0 = NULL input -> exercise null-pointer error branch
   1 = FORWARD_TCP_T with string target
   2 = MODULE0_T (module function zero-params)
   3 = FORCE_SEND_SOCKET_T (resolvehost/find_si path)
   4 = CFG_SELECT_T
   5 = chain of many actions (forward -> module -> force_send) to exercise recursion
*/
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data) return 0;
    uint8_t mode = data[0] % 6;
    struct action *root = NULL;
    int ret = 0;

    switch (mode) {
    case 0:
        /* call with NULL to hit the early null-pointer guard in fix_actions */
        fix_actions(NULL);
        return 0;
    case 1: {
        /* FORWARD_TCP_T with a string target */
        const char *s = (size > 2 && data[1] < 128) ? (char*)(data+2) : "example.com";
        /* build a small null-terminated string safely */
        char buf[128];
        size_t copylen = (size > 2) ? (size - 2) : 0;
        if (copylen > (sizeof(buf)-1)) copylen = sizeof(buf)-1;
        if (copylen > 0) memcpy(buf, data+2, copylen);
        buf[copylen] = '\0';
        root = mk_forward_string(FORWARD_TCP_T, buf, 5060);
        break;
    }
    case 2:
        root = mk_module0("dummymod");
        break;
    case 3:
        root = mk_force_send_socket("localhost", 5060, PROTO_TCP);
        break;
    case 4:
        root = mk_cfg_select("groupA", 1);
        break;
    case 5: {
        /* chain: forward -> module -> force_send */
        struct action *a1 = mk_forward_string(FORWARD_TCP_T, "10.0.0.1", 5060);
        struct action *a2 = mk_module0("m");
        struct action *a3 = mk_force_send_socket("localhost", 5060, PROTO_TCP);
        if (!a1 || !a2 || !a3) {
            free_actions(a1); free_actions(a2); free_actions(a3);
            return 0;
        }
        a1->next = a2; a2->next = a3;
        root = a1;
        break;
    }
    default:
        return 0;
    }

    /* call the function under test */
    ret = fix_actions(root);
    /* clean up (some code inside fix_actions may have replaced strings/pointers -
       free_actions attempts best-effort cleanup) */
    free_actions(root);
    (void)ret;
    return 0;
}
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "./core/dns_cache.h"
#include "./core/str.h"
#include "./core/rand/kam_rand.h"

extern void fastrand_seed(unsigned int seed);
extern unsigned int cryptorand(void);
extern void init_named_flags();
extern int register_builtin_modules();
extern void ksr_cfg_print_initial_state(void);
extern int yyparse (void);
extern int print_rls();
extern int init_dst_set();
extern int pv_reinit_buffer();
extern int sr_core_ert_init();
extern int user2uid(int *uid, int *gid, char *user);

static int static_int = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    str name;
    name.s = (char*)data;
    name.len = size;
	struct ip_addr *tmp_ip = str2ip(&name);
    unsigned short port;

    // str new_name;
    // new_name.s = (char*)data;
    // new_name.len = size;
    // struct ip_addr *ip;
    // ip->af = AF_INET;
    // ip->len = 4;
    // unsigned char v4_mapped[4] = { 192,0,2,1 };
    // memcpy(ip->u.addr, v4_mapped, 4);
    // init_dns_cache();
	// dns_get_ip(&new_name, ip, 0);
	fastrand_seed(cryptorand());
	srandom(cryptorand());

	/*register builtin  modules*/
	register_builtin_modules();

	/* init named flags */
	init_named_flags();
    ksr_cfg_print_initial_state();
    // if (static_int == 0) {
    //     static_int += 1;
    //     alarm(3);
    //     yyparse();
    // }

    destroy_dns_cache();
    print_rls();
    init_dst_set();
    int uid = 0;
    int gid = 0;
    char *user = "1000";
    user2uid(&uid, &gid, user);
    // pv_reinit_buffer();
    // sr_core_ert_init();

    return 0;
}
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
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

/* include the route structures you uploaded */
#include "./core/route_struct.h"
#include "./core/mem/pkg.h"
#include "./core/ip_addr.h"
#include "./core/ut.h"

/* global flags (main.c uses these); set to 0 so parsing allows all protocols */
extern int tcp_disable; // = 0;
extern int tls_disable; // = 0;
extern int sctp_disable; // = 0;
extern char *cfg_file; // = NULL;

int fix_cfg_file(void);
int parse_phostport(char *s, char **host, int *hlen, int *port, int *proto);
int parse_proto(unsigned char *s, long len, int *proto);

/* ---------------------- libFuzzer entrypoint ---------------------------- */

/*
 Modes:
 0 = parse_proto: feed 3 or 4 bytes, try to map to a protocol
 1 = parse_phostport: fuzz a string and see how host/port/proto parse
 2 = fix_cfg_file: set cfg_file to the fuzz data and call fix_cfg_file()
*/
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;
    uint8_t mode = data[0] % 3;

    if (mode == 0) {
        /* proto parse */
        size_t len = size >= 4 ? 4 : (size >= 3 ? 3 : size);
        if (len < 3) return 0;
        unsigned char buf[5] = {0,0,0,0,0};
        memcpy(buf, data+1, len > 0 ? len : 0);
        int proto = -1;
        (void)parse_proto(buf, (long)len, &proto);
        /* no further action */
    } else if (mode == 1) {
        /* host:port parse */
        /* make a nul-terminated mutable string from data */
        size_t slen = size - 1;
        if (slen == 0) return 0;
        char *s = malloc(slen + 1);
        if (!s) return 0;
        memcpy(s, data + 1, slen);
        s[slen] = '\0';
        char *host = NULL;
        int hlen = 0, port = 0, proto = 0;
        parse_phostport(s, &host, &hlen, &port, &proto);
        /* Do not free host because it points into s; free s */
        free(s);
    } else {
        /* fix_cfg_file: set cfg_file to a small string derived from bytes */
        size_t slen = size - 1;
        if (slen == 0) return 0;
        char *s = malloc(slen + 1);
        if (!s) return 0;
        memcpy(s, data + 1, slen);
        s[slen] = '\0';
        /* set global and call */
        /* free previous if any */
        if (cfg_file && cfg_file[0] != '\0') {
            free(cfg_file);
        }
        cfg_file = s;
        (void)fix_cfg_file();
        /* fix_cfg_file may replace cfg_file with a malloc'ed path -> free it */
        if (cfg_file) {
            free(cfg_file);
            cfg_file = NULL;
        }
    }
    return 0;
}#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* include the route structures you uploaded */
#include "./core/route_struct.h"
#include "./core/mem/pkg.h"
#include "./core/ip_addr.h"
#include "./core/ut.h"
#include "./core/io_wait.h"

void udpworker_task_exec(void *param);

/* Control knobs for the stubs: set by the fuzz entrypoint (first byte) */
static int g_stub_enable_net_event = 0;   /* cause sr_event_enabled(SREV_NET_DGRAM_IN) to be true */
static int g_stub_enable_stun_event = 0;  /* cause sr_event_enabled(SREV_STUN_IN) to be true */
static int g_stub_event_exec_ret = 0;     /* what sr_event_exec returns (0 means not handled) */
static int g_stub_stun_ret = 0;           /* what stun_process_msg returns (0 success) */

typedef struct udpworker_task
{
	char *buf;
	int len;
	receive_info_t rcv;
} udpworker_task_t;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 2) return 0;

    uint8_t flags = data[0];
    g_stub_enable_net_event = !!(flags & 0x1);
    g_stub_enable_stun_event = !!(flags & 0x2);
    g_stub_event_exec_ret = (flags & 0x4) ? -1 : 0;
    g_stub_stun_ret = (flags & 0x8) ? 1 : 0;

    size_t payload_len = size - 1;
    if (payload_len > BUF_SIZE) payload_len = BUF_SIZE;

    /* allocate and fill a task object on heap */
    udpworker_task_t *task = (udpworker_task_t *)malloc(sizeof(udpworker_task_t));
    if (!task) return 0;
    task->buf = (char *)malloc(payload_len + 1);
    if (!task->buf) { free(task); return 0; }
    memcpy(task->buf, data + 1, payload_len);
    task->buf[payload_len] = '\0';
    task->len = (int)payload_len;

    /* prepare receive_info: set src_port from last payload byte if present
       (allows fuzz to generate src_port==0 edge case) */
    memset(&task->rcv, 0, sizeof(task->rcv));
    if (payload_len > 0) {
        task->rcv.src_port = (unsigned char)task->buf[payload_len - 1];
    } else {
        task->rcv.src_port = 5060; /* default non-zero port */
    }

    /* call the function under test */
    udpworker_task_exec((void *)task);

    /* cleanup */
    free(task->buf);
    free(task);

    return 0;
}
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "./core/ppcfg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;

    /* allocate copy with project allocator */
    char *buf = malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    pp_substdef_add(data, 0);
    pp_subst_run(&buf);
    pp_define_core();
    free(buf);

    return 0;
}
// fuzz_fix_rval_expr.c
// Fuzz harness for fix_rval_expr from rvalue.c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/*
  IMPORTANT: this harness expects to be compiled and linked with the project's
  sources (rvalue.c and project headers). It uses the project's public helpers:
    - mk_rval_expr_v / mk_rval_expr1 / mk_rval_expr2
    - rve_destroy (or rve_destroy)
    - fix_rval_expr

  Include paths in the compile command should point to where the project's
  headers (rvalue.h, core/... etc) live.
*/
#include "./core/rvalue.h" /* project header that declares the types and helpers */
#include "./core/str.h"
/* If your project uses a different include path, adjust the -I flags when compiling. */

struct rvalue *rval_new_re(str *s);

/* Helper: clamp size to avoid huge allocations during harness run */
static size_t clamp_size(size_t s, size_t max) {
    return (s > max) ? max : s;
}

/* Build a simple constant long node from 8 bytes (if available) */
static struct rval_expr *build_long_rve(const uint8_t *data, size_t size) {
    long v = 0;
    size_t take = (size >= 8) ? 8 : size;
    for (size_t i = 0; i < take; ++i) {
        v = (v << 8) | data[i];
    }
    return mk_rval_expr_v(RV_LONG, (void *)(intptr_t)v, NULL);
}

/* Build a simple string rve (mk_rval_expr_v expects a 'str *') */
static struct rval_expr *build_str_rve(const uint8_t *data, size_t size) {
    str s;
    size_t sl = clamp_size(size, 256);
    if (sl == 0) {
        /* empty string */
        static const char empty_c = '\0';
        s.s = (char *)&empty_c;
        s.len = 0;
        return mk_rval_expr_v(RV_STR, &s, NULL);
    }
    /* allocate a small buffer on heap and copy the data so mk_rval_expr_v
       will duplicate it safely */
    char *buf = malloc(sl + 1);
    if (!buf) return NULL;
    memcpy(buf, data, sl);
    buf[sl] = '\0';
    s.s = buf;
    s.len = (int)sl;
    struct rval_expr *r = mk_rval_expr_v(RV_STR, &s, NULL);
    struct rvalue * val = rval_new_re(&s);
    rval_destroy(val);
    free(buf);
    return r;
}

/* Build either a literal rve or a simple op tree depending on input */
static struct rval_expr *build_expr_from_input(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    uint8_t discriminator = data[0];
    const uint8_t *p = data + 1;
    size_t rem = (size > 1) ? size - 1 : 0;

    /* pick a simple pattern based on discriminator */
    switch (discriminator % 6) {
        case 0: /* single long */
            return build_long_rve(p, rem);
        case 1: /* single string */
            return build_str_rve(p, rem);
        case 2: { /* unary op: STRLEN or UMINUS */
            struct rval_expr *child;
            if (rem == 0) return build_long_rve(p, rem);
            if (p[0] & 1) child = build_long_rve(p+1, rem>1?rem-1:0);
            else child = build_str_rve(p+1, rem>1?rem-1:0);
            if (!child) return NULL;
            enum rval_expr_op op = (p[0] & 1) ? RVE_UMINUS_OP : RVE_STRLEN_OP;
            struct rval_expr *r = mk_rval_expr1(op, child, NULL);
            return r;
        }
        case 3: { /* binary numeric ops: +, -, *, / */
            size_t half = rem/2;
            struct rval_expr *l = build_long_rve(p, half);
            struct rval_expr *r = build_long_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op ops[4] = { RVE_PLUS_OP, RVE_MINUS_OP, RVE_MUL_OP, RVE_DIV_OP };
            enum rval_expr_op op = ops[(p[0]) % 4];
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
        case 4: { /* string concat / compare */
            size_t half = rem/2;
            struct rval_expr *l = build_str_rve(p, half);
            struct rval_expr *r = build_str_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op ops[3] = { RVE_CONCAT_OP, RVE_STREQ_OP, RVE_STRDIFF_OP };
            enum rval_expr_op op = ops[(p[0]) % 3];
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
        default: { /* match (regex) or select opt: build right side as string */
            size_t half = rem/2;
            struct rval_expr *l = build_str_rve(p, half);
            struct rval_expr *r = build_str_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op op = (p[0] & 1) ? RVE_MATCH_OP : RVE_SELVALOPT_OP;
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
    }
}

/* Actual libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    struct rval_expr *rve = build_expr_from_input(data, size);
    if (!rve) return 0;

    /* Call the fixer under test */
    /* fix_rval_expr returns 0 on success, <0 on error (see rvalue.c) */
    fix_rval_expr((void *)rve);

    /* free everything we allocated */
    rve_destroy(rve); /* rve_destroy frees subtrees and pkg_free the node */
    return 0;
}
// fuzz_fix_rval_expr.c
// Fuzz harness for fix_rval_expr from rvalue.c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/*
  IMPORTANT: this harness expects to be compiled and linked with the project's
  sources (rvalue.c and project headers). It uses the project's public helpers:
    - mk_rval_expr_v / mk_rval_expr1 / mk_rval_expr2
    - rve_destroy (or rve_destroy)
    - fix_rval_expr

  Include paths in the compile command should point to where the project's
  headers (rvalue.h, core/... etc) live.
*/
#include "./core/rvalue.h" /* project header that declares the types and helpers */
#include "./core/rvalue.c" /* project header that declares the types and helpers */
#include "./core/str.h"
/* If your project uses a different include path, adjust the -I flags when compiling. */

struct rvalue *rval_new_re(str *s);

/* Helper: clamp size to avoid huge allocations during harness run */
static size_t clamp_size(size_t s, size_t max) {
    return (s > max) ? max : s;
}

/* Build a simple constant long node from 8 bytes (if available) */
static struct rval_expr *build_long_rve(const uint8_t *data, size_t size) {
    long v = 0;
    size_t take = (size >= 8) ? 8 : size;
    for (size_t i = 0; i < take; ++i) {
        v = (v << 8) | data[i];
    }
    return mk_rval_expr_v(RV_LONG, (void *)(intptr_t)v, NULL);
}

/* Build a simple string rve (mk_rval_expr_v expects a 'str *') */
static struct rval_expr *build_str_rve(const uint8_t *data, size_t size) {
    str s;
    size_t sl = clamp_size(size, 256);
    if (sl == 0) {
        /* empty string */
        static const char empty_c = '\0';
        s.s = (char *)&empty_c;
        s.len = 0;
        return mk_rval_expr_v(RV_STR, &s, NULL);
    }
    /* allocate a small buffer on heap and copy the data so mk_rval_expr_v
       will duplicate it safely */
    char *buf = malloc(sl + 1);
    if (!buf) return NULL;
    memcpy(buf, data, sl);
    buf[sl] = '\0';
    s.s = buf;
    s.len = (int)sl;
    struct rval_expr *r = mk_rval_expr_v(RV_STR, &s, NULL);
    struct rvalue * val = rval_new_re(&s);
    rval_destroy(val);
    free(buf);
    return r;
}

/* Build either a literal rve or a simple op tree depending on input */
static struct rval_expr *build_expr_from_input(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    uint8_t discriminator = data[0];
    const uint8_t *p = data + 1;
    size_t rem = (size > 1) ? size - 1 : 0;

    /* pick a simple pattern based on discriminator */
    switch (discriminator % 6) {
        case 0: /* single long */
            return build_long_rve(p, rem);
        case 1: /* single string */
            return build_str_rve(p, rem);
        case 2: { /* unary op: STRLEN or UMINUS */
            struct rval_expr *child;
            if (rem == 0) return build_long_rve(p, rem);
            if (p[0] & 1) child = build_long_rve(p+1, rem>1?rem-1:0);
            else child = build_str_rve(p+1, rem>1?rem-1:0);
            if (!child) return NULL;
            enum rval_expr_op op = (p[0] & 1) ? RVE_UMINUS_OP : RVE_STRLEN_OP;
            struct rval_expr *r = mk_rval_expr1(op, child, NULL);
            return r;
        }
        case 3: { /* binary numeric ops: +, -, *, / */
            size_t half = rem/2;
            struct rval_expr *l = build_long_rve(p, half);
            struct rval_expr *r = build_long_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op ops[4] = { RVE_PLUS_OP, RVE_MINUS_OP, RVE_MUL_OP, RVE_DIV_OP };
            enum rval_expr_op op = ops[(p[0]) % 4];
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
        case 4: { /* string concat / compare */
            size_t half = rem/2;
            struct rval_expr *l = build_str_rve(p, half);
            struct rval_expr *r = build_str_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op ops[3] = { RVE_CONCAT_OP, RVE_STREQ_OP, RVE_STRDIFF_OP };
            enum rval_expr_op op = ops[(p[0]) % 3];
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
        default: { /* match (regex) or select opt: build right side as string */
            size_t half = rem/2;
            struct rval_expr *l = build_str_rve(p, half);
            struct rval_expr *r = build_str_rve(p+half, rem-half);
            if (!l || !r) { if(l) rve_destroy(l); if(r) rve_destroy(r); return NULL; }
            enum rval_expr_op op = (p[0] & 1) ? RVE_MATCH_OP : RVE_SELVALOPT_OP;
            struct rval_expr *res = mk_rval_expr2(op, l, r, NULL);
            return res;
        }
    }
}

static const enum rval_expr_op all_ops[] = {
    RVE_NONE_OP,
    RVE_RVAL_OP,
    RVE_UMINUS_OP,
    RVE_BOOL_OP,
    RVE_LNOT_OP,
    RVE_BNOT_OP,
    RVE_MUL_OP,
    RVE_DIV_OP,
    RVE_MOD_OP,
    RVE_MINUS_OP,
    RVE_BAND_OP,
    RVE_BOR_OP,
    RVE_BXOR_OP,
    RVE_BLSHIFT_OP,
    RVE_BRSHIFT_OP,
    RVE_LAND_OP,
    RVE_LOR_OP,
    RVE_GT_OP,
    RVE_GTE_OP,
    RVE_LT_OP,
    RVE_LTE_OP,
    RVE_IEQ_OP,
    RVE_IDIFF_OP,
    RVE_IPLUS_OP,
    RVE_PLUS_OP,
    RVE_EQ_OP,
    RVE_DIFF_OP,
    RVE_CONCAT_OP,
    RVE_STRLEN_OP,
    RVE_STREMPTY_OP,
    RVE_STREQ_OP,
    RVE_STRDIFF_OP,
    RVE_MATCH_OP,
    RVE_SELVALEXP_OP,
    RVE_SELVALOPT_OP,
    RVE_DEFINED_OP,
    RVE_NOTDEFINED_OP,
    RVE_LONG_OP,
    RVE_STR_OP
};

/* Actual libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    struct rval_expr *rve = build_expr_from_input(data, size);
    if (!rve) return 0;
    struct rval_expr *rve2 = build_expr_from_input(data, size);
    if (!rve2) return 0;
    size_t n_ops = sizeof(all_ops) / sizeof(all_ops[0]);
    enum rval_expr_op chosen = all_ops[data[0] % n_ops];

    enum rval_type tmp_type = RV_STR;

    rve2->op = chosen;
    rve_op_is_assoc(rve2->op);
    rve_op_is_commutative(rve2->op);

    /* Call the fixer under test */
    /* fix_rval_expr returns 0 on success, <0 on error (see rvalue.c) */
    fix_rval_expr((void *)rve);

    /* free everything we allocated */
    rve_destroy(rve); /* rve_destroy frees subtrees and pkg_free the node */
    // rve_destroy(rve2); /* rve_destroy frees subtrees and pkg_free the node */
    return 0;
}
