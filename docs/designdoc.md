# ebpf-http-scan: design doc

**Date:** 2026-09-25
**Status:** Draft. M0 (environment) is implemented in `scripts/`; M1–M4 are planned.
**Owner:** Kushal Krishnappa

---

## 0. Why this exists

This is a learning project: a deliberately small eBPF HTTP request scanner that covers every layer of a runtime API-security sensor, from kernel capture to a redacted finding. Each layer is kept small enough to understand end to end.

**The pipeline:**

| Stage | This project |
|---|---|
| Kernel capture | `bpf/capture.bpf.c`: fentry/fexit `tcp_recvmsg` (M1), `SSL_read` uprobes (M3), `events` ringbuf |
| Userspace parse | `internal/reasm` + `internal/httpparse` (Go, HTTP/1.x) |
| Field isolation | `internal/rules`: each matcher returns `[]path`, giving one Finding per path |
| Redaction | `internal/finding`: value redacted on stdout; raw goes to `vault/<ref>.json` |

**Core principle:** *The kernel sees bytes cheaply; userspace understands them safely.*

## 1. Decisions made

| Decision | Choice | Why |
|---|---|---|
| Toolchain | **C for the eBPF programs + Go userspace (cilium/ebpf + bpf2go)** | Leanest option: one small C file per hook, and the rest is ordinary Go. |
| Capture scope | **Plain HTTP first (M1), then TLS via uprobes (M3)** | Each step is small and works on its own. |
| Where it ends | **A redacted finding on stdout, with raw data in a local vault file** | Keeps the privacy story without cloud storage, gRPC or queues. |
| Linux environment | **Any Linux with BTF (tested on Ubuntu 24.04, kernel 6.8).** On a Mac: a Lima Ubuntu 24.04 arm64 VM | eBPF needs a real Linux kernel. |
| Parsing location | **Approach C:** userspace parsing + an optional in-kernel scan experiment (M4) | Lets you answer "why not parse in the kernel?" from experience. |

**Rejected:**
- Rust + libbpf-rs: more setup.
- bpftrace + Python: nothing to learn about maps, ringbuf or CO-RE.
- Docker Desktop privileged container: LinuxKit kernel with uncertain BTF/fentry support.
- A separate ingest gateway with object storage: a distributed-systems topic of its own, deferred.
- Pure in-kernel scanning (Approach B): fragile, and hard to get past the verifier.

## 2. Architecture

```
curl ──► testserver (Go net/http, :8080 plain)   |  python/nginx HTTPS :8443 (M3)
              │ kernel: fentry+fexit tcp_recvmsg  |  uprobe+uretprobe SSL_read (libssl.so.3)
              ▼
      BPF_MAP_TYPE_RINGBUF "events"
      struct event { u64 ts; u32 pid; u32 len; u64 conn_id; u8 source; u8 truncated; char comm[16]; u8 data[4096]; }
              ▼
  cmd/agent (Go, root)
    internal/capture   load + attach (bpf2go objects), read ringbuf → Chunk{ConnID, PID, Comm, Data}
    internal/reasm     per-ConnID byte buffer, idle eviction, caps
    internal/httpparse bytes → Request{Method, URI, Query, Headers[], Body} (HTTP/1.x, Content-Length only)
    internal/rules     rules.json → matchers → []Match{RuleID, Class, Severity, Location, Path, Value}
    internal/finding   Match → redacted JSON on stdout; raw request → vault/<ref>.json (0600)
```

### Repo layout
```
ebpf-http-scan/
  README.md                 # setup + demo commands
  LEARNINGS.md              # journal: verifier errors, surprises, numbers
  go.mod
  bpf/
    vmlinux.h               # generated from the running kernel, gitignored
    common.h                # struct event, constants (MAX_DATA 4096)
    capture.bpf.c           # M1: tcp_recvmsg fentry/fexit
    tls.bpf.c               # M3: SSL_read uprobe/uretprobe
    scan.bpf.c              # M4: optional in-kernel Cookie scan
  internal/capture/         # //go:generate bpf2go …; loader.go
  internal/reasm/
  internal/httpparse/
  internal/rules/           # rules.go, matchers.go, rules.json
  internal/finding/         # redact.go, vault.go
  cmd/agent/main.go         # flags: -port 8080 -tls-lib /usr/lib/aarch64-linux-gnu/libssl.so.3 -vault ./vault
  testserver/main.go        # plain HTTP server that echoes 200
  scripts/setup-vm.sh       # installs the toolchain on Linux (natively or inside the Lima VM)
  scripts/setup-mac.sh      # Mac only: installs Lima and creates the VM
  scripts/demo.sh           # sends attack requests with curl, asserts findings with jq
```

## 3. Components

### 3.1 `bpf/capture.bpf.c` (M1)
- **Maps:**
  - `events`: RINGBUF, 256 KiB.
  - `config`: ARRAY[1] `{ u16 target_port }`, written by the agent. It's the filter, and also acts as a kill switch (port 0 means off).
  - `pending`: HASH keyed by `pid_tgid`, value `{ u64 ubuf_ptr; u64 conn_id }`, 10240 entries. It stashes the user buffer pointer between fentry and fexit.
  - `drops`: PERCPU_ARRAY[1] u64. Counts ringbuf reserve failures.
- **`fentry/tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)`** (kernel ≥ 5.19 signature; 6.8 on Ubuntu 24.04):
  1. Read the local port `BPF_CORE_READ(sk, __sk_common.skc_num)`. Skip if it isn't `config.target_port`.
  2. If `msg->msg_iter.iter_type == ITER_UBUF` (a plain `read()`), stash `msg->msg_iter.ubuf`. Otherwise skip for v1 (ITER_IOVEC is a stretch goal; a full sensor handles both, using `bpf_core_enum_value_exists` to stay portable across kernels).
  3. `conn_id = bpf_get_socket_cookie(sk)`. If that helper is rejected for this program type, fall back to `(u64)sk`.
- **`fexit/tcp_recvmsg(..., int ret)`:** look up `pending` and delete the entry. If `ret > 0`, reserve an event, set `len = ret`, and if `ret > MAX_DATA` set `truncated = 1`. Read `n = ret & (MAX_DATA-1)`; this masking is the verifier-friendly bound. Then `bpf_probe_read_user(data, n, ubuf)` and submit. If the reserve fails, increment `drops`.
- **Fallback, if the iov_iter work stalls:** `tracepoint/syscalls/sys_enter_read` + `sys_exit_read`, filtered by the server's PID. This is simpler, but you lose socket-level context. Log it in LEARNINGS.md either way.

### 3.2 `bpf/tls.bpf.c` (M3)
- `uprobe/SSL_read(SSL *ssl, void *buf, int num)`: stash `{buf, ssl}` keyed by `pid_tgid`.
- `uretprobe/SSL_read`: if `ret > 0`, emit an event with `source = TLS`, `conn_id = (u64)ssl`, copying at most `MAX_DATA` bytes of `buf`.
- Attach with cilium/ebpf `link.OpenExecutable(libssl).Uprobe("SSL_read", …)` / `.Uretprobe(...)`. Server: `python3` `http.server` wrapped in `ssl` on :8443, which dynamically links `libssl.so.3`.
- **Avoiding double capture:** the TLS server port (8443) isn't the plain `target_port`, so `capture.bpf.c` never sees its ciphertext. The general fix is to hook `SSL_set_fd`, record which sockets belong to TLS sessions, and have the TCP probes skip those sockets. Linking the socket is a stretch goal.

### 3.3 `internal/reasm`
- `Push(chunk) []Request`. It appends to `buf[connID]`, then asks httpparse for complete requests, consumes the bytes they used, and keeps any remainder.
- **Caps:** header block ≤ 64 KiB (`MAX_HEADER_BYTES`) and body ≤ 1 MiB. If a cap is exceeded, drop the buffer and count a `parse_overflow`.
- **Idle eviction:** buffers untouched for 30 s are deleted. That's a sweep every 10 s. There's no close tracking in v1; the `tcp_set_state`/close hook is a stretch goal.

### 3.4 `internal/httpparse`
- A hand-written minimal parser, so you learn the framing:
  1. find `\r\n\r\n` (if it's missing, the request is incomplete)
  2. parse the request line
  3. parse headers with `net/textproto`, keeping order and original names (≤ 100 headers)
  4. read the body by `Content-Length`
- `Transfer-Encoding: chunked` → return `ErrUnsupported`. This is a deliberate scope limit.
- The query is parsed with `url.ParseQuery`.
- Output: `Request{Method, URI, Path, Query url.Values, Headers []Header{Name, Value}, Body []byte, ContentType}`.

### 3.5 `internal/rules`
- The `rules.json` schema: `{id, class, severity, description, location, target, matcher, pattern?}`.
  - `location`: one of `request_header`, `query_param`, `body_json`.
  - `target`: a header or parameter name, or `"*"` for all of them.
  - `matcher`: one of `sqli`, `xss`, `regex`, `weak_session`, `jwt_none`, `ssn`, `luhn_card`.
- **Field isolation:** a matcher is `func(value string) bool`. The engine loops over the candidate fields for the rule's location and emits **one Match per matching field**. The `Path` is the header name, the query parameter name, or the JSON path (for example `$.user.ssn`).
- **Starter rules:**

| ID | Class | Location / target | Matcher |
|---|---|---|---|
| SQLI-1 | sql_injection | request_header / `*` | sqli regex set |
| SQLI-2 | sql_injection | query_param / `*` | sqli |
| WEAK-1 | weak_id | request_header / `Cookie` (per cookie name) | weak_session: value ≤ 8 chars or all digits |
| AUTH-1 | weak_auth | request_header / `Authorization` | jwt_none: bearer JWT with `alg: none` |
| SD-1 | sensitive_data | body_json / `*` | ssn regex `\b\d{3}-\d{2}-\d{4}\b` |
| SD-2 | sensitive_data | body_json / `*` | luhn_card |

- The SQLi and XSS matchers are **naive regex on purpose** (for example `(?i)(\bunion\b.+\bselect\b|'\s*or\s*'?\d+'?\s*=|--\s|;\s*drop\s)`). Write down in LEARNINGS.md why real scanners use tokenizing matchers instead (false positives, encodings, evasion).

### 3.6 `internal/finding`
- The Finding JSON line on stdout:
  `{ts, rule_id, class, severity, location, path, value:"<redacted len=N sha256:8hex>", ref, conn_id, pid, comm, method, uri_path}`
  - `uri_path` has the query stripped, because query values may be sensitive.
- `ref` is a UUIDv4, one per request that produced any finding.
- **Vault:** `vault/<ref>.json` (mode 0600) holds the raw request `{method, uri, headers[{name, value}], body}`. It stands in for an access-controlled store (for example an object-storage bucket keyed by `<ref>`), so findings can travel freely while raw values stay behind.
- **Invariant, enforced by a test:** no raw matched value ever appears on stdout.

### 3.7 `cmd/agent`
- Sets `rlimit` memlock (`rlimit.RemoveMemlock()`), loads the objects, writes `config.target_port`, attaches fentry/fexit (and the uprobes if `-tls-lib` is set), and reads the ringbuf in a loop feeding `reasm` → `httpparse` → `rules` → `finding`.
- Every 10 s it prints stats: events, drops (the sum of `drops` across CPUs), parse errors, overflows, findings.
- On SIGINT it closes the links cleanly.

## 4. Data flow: one request end to end
`curl -H "User-Agent: ' OR 1=1 --" http://localhost:8080/search?q=x`
1. testserver `read()` → `tcp_recvmsg` → fentry sees port 8080 and stashes the ubuf pointer.
2. fexit (ret=112) → ringbuf event {conn_id=cookie, len=112, data}.
3. The agent reads the event → `reasm.Push` → `httpparse` finds `\r\n\r\n` → Request.
4. Rule SQLI-1 iterates the headers; the sqli matcher hits on `User-Agent`, giving Match{SQLI-1, REQUEST_HEADER, path:"User-Agent"}.
5. finding prints `{rule_id:"SQLI-1", location:"request_header", path:"User-Agent", value:"<redacted len=11 sha256:…>", ref:"…"}` and writes `vault/<ref>.json`.

## 5. Error handling

| Failure | Behaviour |
|---|---|
| Ringbuf full | `bpf_ringbuf_reserve` returns NULL → `drops++`. The agent reports it. Nothing blocks; loss is counted, not hidden. |
| Read larger than 4096 bytes | `truncated=1`. Reassembly marks the connection as lossy and skips parsing until it's evicted. Log it. |
| Incomplete request | Keep buffering until the caps or the idle timeout. |
| Chunked or unsupported framing | Counted as `unsupported`, and the buffer is dropped. |
| Cap exceeded | `parse_overflow++`, and the buffer is dropped. |
| Verifier rejects the program | The agent prints the full verifier log (`ebpf.VerifierError` with `%+v`). Copy the errors into LEARNINGS.md. |
| Target port 0 | Probes stay attached but do nothing (a cheap kill switch). |

## 6. Testing
- **Unit (Go, runs on any OS, including macOS):**
  - httpparse: request line, headers, Content-Length body, incomplete input, chunked giving ErrUnsupported, header caps.
  - reasm: a request split across 3 chunks, 2 pipelined requests in 1 chunk, eviction.
  - rules: table tests. Each rule gets a positive and a negative case, **and the Path is asserted**. A request with two bad headers must produce two Matches.
  - finding: the redaction format, and a test that the raw value never appears in the output.
- **Integration (on Linux):** `scripts/demo.sh` starts testserver and agent, sends one curl per rule, and asserts each expected `{rule_id, path}` with `jq`. It sends clean traffic and asserts there are zero findings. It also checks that the vault file exists with mode 0600.
- **M4 measurement:**
  - `sysctl kernel.bpf_stats_enabled=1`, then `bpftool prog show` for `run_time_ns / run_cnt`.
  - Use `hey` or `wrk` against testserver with the agent off, with M2 running, and with M4 running.
  - Record requests/s, CPU usage, and the per-program nanoseconds in LEARNINGS.md.

## 7. Milestones and acceptance criteria

| # | Milestone | Done when | Concepts covered |
|---|---|---|---|
| M0 | Environment | Linux toolchain installed (natively, or in the Lima VM on a Mac); `bpftool btf dump` works; a hello fentry program prints via ringbuf | BTF/CO-RE, vmlinux.h, bpf2go, loading and privileges |
| M1 | Plain capture | `curl :8080` shows the raw request bytes in the agent; port filter works; drops counter works | fentry vs kprobe, entry/exit stashing, ringbuf, verifier bounds masking, socket cookie |
| M2 | Parse → match → isolate → redact | `demo.sh` passes all plain-HTTP cases; unit tests green | Reassembly, HTTP/1.1 framing, field isolation (one finding per path), redaction boundary |
| M3 | TLS | An HTTPS request to :8443 produces the same findings through the `SSL_read` uprobe | Why TC/XDP can't do it, uprobe mechanics, library discovery, gaps (Go/Java/rustls, HTTP/2) |
| M4 | In-kernel scan experiment (optional) | `scan.bpf.c` emits the offset of `cookie:` within the first 512 bytes (per-CPU scratch, bounded loop or `bpf_loop`); verifier errors and a perf comparison are recorded | "Why not parse in the kernel?", answered from experience |

**Stretch goals (after M4):**
- `tcp_set_state` close tracking
- ITER_IOVEC support
- the `SSL_set_fd` socket linkage
- `tcp_sendmsg` for responses (response-side rules such as SSN in a response)
- `ss`-style container attribution via cgroup id

## 8. Environment setup (M0 reference)
See the README for the full steps. In short:

```bash
# Mac only: create a Linux VM first, then run the Linux steps inside it
scripts/setup-mac.sh
limactl shell --workdir "$PWD" ebpf

# Linux (native, or inside the VM)
scripts/setup-vm.sh            # apt packages, Go, bpf/vmlinux.h, checks
go generate ./...              # bpf2go compiles bpf/*.c and generates Go bindings
sudo go run ./cmd/agent -port 8080
```

**Checks to warm up with first** (`setup-vm.sh` runs both):
- `sudo bpftrace -e 'kfunc:tcp_recvmsg { printf("%s\n", comm); }'` confirms fentry works on this kernel.
- `sudo bpftrace -e 'uretprobe:/usr/lib/aarch64-linux-gnu/libssl.so.3:SSL_read { printf("%d\n", retval); }'` confirms uprobes work (use `x86_64-linux-gnu` on amd64).

## 9. Risks and open questions
- **fentry on arm64:** supported on 6.x. Confirm with the bpftrace check above. The fallback is kprobes.
- **`bpf_get_socket_cookie` from fentry:** if the verifier rejects it, use the `sk` pointer as the connection ID and note why the cookie is better (it's stable and never reused while the socket lives).
- **Go's net/http reads:** confirm that the server's reads arrive as ITER_UBUF on 6.8. If not, implement ITER_IOVEC reading the first iovec only.
- **Capture side:** capture inbound traffic at the server (`tcp_recvmsg` on the server's port) rather than the client's `tcp_sendmsg`, since that's what a sensor protecting a workload sees.
