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
}