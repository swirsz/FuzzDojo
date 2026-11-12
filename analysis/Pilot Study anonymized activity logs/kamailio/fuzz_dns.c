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
