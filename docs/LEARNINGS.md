# Learnings

## M1: tcp_recvmsg capture (2026-09-25, Ubuntu 24.04, kernel 6.8.0-134-generic, arm64)

- **`config` is taken.** `vmlinux.h` has `typedef struct config_s config;`, so a map named `config` fails with "redefinition of 'config' as different kind of symbol". The map is `config_map` instead. Any global in a BPF program shares a namespace with every kernel type.
- **`bpf2go -type event` couldn't find `struct event`.** clang only emits BTF for types reachable from globals or function signatures. A type used only through a local pointer (`struct event *e = bpf_ringbuf_reserve(...)`) is missing. The fix is the usual unused global: `const struct event *unused_event __attribute__((unused));`.
- **Verifier bound:** a plain clamp (`u32 n = ret; if (n > MAX_DATA) n = MAX_DATA;`) before `bpf_probe_read_user(e->data, n, ...)` was accepted as written. The `& (MAX_DATA-1)` mask fallback wasn't needed.
- **`bpf_get_socket_cookie(sk)` works from fentry** (tracing programs take a BTF `struct sock *`). Cookies are small, increasing integers (`2f`, `3024`, `3025`), so no `(u64)sk` fallback was needed.
- **Go net/http reads are ITER_UBUF** on 6.8: every request was captured without any ITER_IOVEC handling.
- **Go reads in 4096-byte pieces.** A request with a 6000-byte header arrived as three events (4096 + 78 + 1915) with the same `conn_id`, and none had `trunc=true`. That's because net/http's bufio reader asks for at most 4 KiB, which matches `MAX_DATA`. Truncation would only happen for a reader with a bigger buffer. Only the unit test (`chunk_test.go`) covers it, so reassembly (M2) must stitch chunks by `conn_id`.
- **`bpftool prog show` lists programs by their own names** (`on_recv_enter`, `on_recv_exit`), not by the function they attach to. Grepping for `tcp_recvmsg` finds nothing, even while the programs are attached.
- **Port filter:** requests to a second testserver on :9090 produced no events.
