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
