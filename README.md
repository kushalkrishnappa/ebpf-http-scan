# ebpf-http-scan

A small eBPF HTTP request scanner: kernel capture (`tcp_recvmsg` fentry/fexit, `SSL_read` uprobes) → Go userspace parse → rule match → redacted findings. Design: [`docs/designdoc.md`](docs/designdoc.md).

## Requirements

- Linux with kernel BTF (`/sys/kernel/btf/vmlinux`). Tested on Ubuntu 24.04 (kernel 6.8), arm64 and amd64.
- An apt-based distro, for the setup script.
- `sudo`, because loading eBPF programs needs root.

> **On a Mac?** eBPF needs a Linux kernel, so first create a Lima VM, then follow the Linux steps inside it. See [Running on macOS](#running-on-macos). Linux users can skip that section.

## Setup

```bash
# clang/llvm, libbpf, bpftool, bpftrace, Go, bpf/vmlinux.h, then run checks
scripts/setup-vm.sh

# Re-run only the environment checks
scripts/setup-vm.sh --check
```

`setup-vm.sh` installs the Go version from `go.mod` if your Go is older. `bpf2go` is pinned as a Go tool dependency, so run it with `go tool bpf2go`. There's nothing to install globally.

## Test server

```bash
go run ./testserver                 # plain HTTP on :8080
go run ./testserver -addr :9090

curl -H "User-Agent: ' OR 1=1 --" 'localhost:8080/search?q=x'
```

It returns 200 with `{status, method, path, body_bytes}` for every request. It reads the whole body before replying, so every request byte goes through `tcp_recvmsg`. It logs only the method, path and body size, never header or query values.

## Running on macOS

`scripts/setup-mac.sh` installs [Lima](https://lima-vm.io) with Homebrew and creates an Ubuntu 24.04 VM named `ebpf`. Your home directory is mounted writable, so the repo is at the same path inside the VM.

```bash
scripts/setup-mac.sh                                            # create/start the VM
limactl shell --workdir "$PWD" ebpf ./scripts/setup-vm.sh       # Linux setup, inside the VM
limactl shell --workdir "$PWD" ebpf                             # open a shell in the VM
```

Run every other command in this README from that VM shell. `VM_NAME`, `VM_CPUS` and `VM_MEMORY` (GiB) override the defaults.
