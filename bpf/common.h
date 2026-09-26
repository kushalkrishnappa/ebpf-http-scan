/* Shared between capture.bpf.c and the Go decoder (internal/capture/chunk.go).
 * If you change struct event, update the offsets in chunk.go too. */
#ifndef __COMMON_H
#define __COMMON_H

#define MAX_DATA 4096
#define COMM_LEN 16

#define SOURCE_TCP 0
#define SOURCE_TLS 1 /* M3 */

/* One ringbuf record per successful tcp_recvmsg on the target port.
 * Layout (x86_64/arm64): ts@0 pid@8 len@12 conn_id@16 source@24
 * truncated@25 comm@26 data@42, sizeof = 4144 (tail padding to 8). */
struct event {
	u64 ts;         /* bpf_ktime_get_ns() */
	u32 pid;        /* tgid */
	u32 len;        /* bytes the kernel returned (may exceed MAX_DATA) */
	u64 conn_id;    /* socket cookie */
	u8 source;      /* SOURCE_* */
	u8 truncated;   /* 1 if len > MAX_DATA */
	char comm[COMM_LEN];
	u8 data[MAX_DATA];
};

/* config_map[0], written by the agent (not "config": vmlinux.h has that typedef). target_port == 0 disables capture. */
struct config {
	u16 target_port;
};

#endif /* __COMMON_H */
