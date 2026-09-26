// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* M1: capture inbound plain-HTTP bytes at the server via tcp_recvmsg.
 *
 * fentry stashes the user buffer pointer (the iov_iter advances during the
 * call, so it must be read on entry); fexit copies the ret bytes the kernel
 * wrote there into a ringbuf event. See docs/designdoc.md §3.1. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Types only used via locals don't reach BTF; this global makes bpf2go
 * -type event able to find struct event. */
const struct event *unused_event __attribute__((unused));

struct pending {
	u64 ubuf;
	u64 conn_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64); /* pid_tgid */
	__type(value, struct pending);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} drops SEC(".maps");

SEC("fentry/tcp_recvmsg")
int BPF_PROG(on_recv_enter, struct sock *sk, struct msghdr *msg, size_t len,
	     int flags, int *addr_len)
{
	u32 zero = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg || cfg->target_port == 0)
		return 0;

	/* skc_num is the local port in host byte order. */
	if (BPF_CORE_READ(sk, __sk_common.skc_num) != cfg->target_port)
		return 0;

	/* v1: plain read()/recv() into one user buffer. ITER_IOVEC (readv,
	 * recvmsg) is a stretch goal. */
	if (BPF_CORE_READ(msg, msg_iter.iter_type) !=
	    bpf_core_enum_value(enum iter_type, ITER_UBUF))
		return 0;

	struct pending p = {
		/* Data lands at ubuf + iov_offset; offset is normally 0 here. */
		.ubuf = (u64)BPF_CORE_READ(msg, msg_iter.ubuf) +
			BPF_CORE_READ(msg, msg_iter.iov_offset),
		.conn_id = bpf_get_socket_cookie(sk),
	};
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&pending, &id, &p, BPF_ANY);
	return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(on_recv_exit, struct sock *sk, struct msghdr *msg, size_t len,
	     int flags, int *addr_len, int ret)
{
	u64 id = bpf_get_current_pid_tgid();
	struct pending *pp = bpf_map_lookup_elem(&pending, &id);
	if (!pp)
		return 0;
	struct pending p = *pp;
	bpf_map_delete_elem(&pending, &id);

	if (ret <= 0)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		u32 zero = 0;
		u64 *d = bpf_map_lookup_elem(&drops, &zero);
		if (d)
			(*d)++; /* per-CPU slot: no atomics needed */
		return 0;
	}

	e->ts = bpf_ktime_get_ns();
	e->pid = id >> 32;
	e->len = ret;
	e->conn_id = p.conn_id;
	e->source = SOURCE_TCP;
	e->truncated = ret > MAX_DATA;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* The verifier must see n <= MAX_DATA. */
	u32 n = ret;
	if (n > MAX_DATA)
		n = MAX_DATA;
	if (bpf_probe_read_user(e->data, n, (void *)p.ubuf) < 0)
		e->len = 0; /* page not resident: report the read with no bytes */

	bpf_ringbuf_submit(e, 0);
	return 0;
}
