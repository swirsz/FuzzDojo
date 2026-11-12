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
