#include <stdint.h>
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
