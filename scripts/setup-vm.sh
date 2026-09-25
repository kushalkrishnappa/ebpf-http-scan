#!/usr/bin/env bash
# VM side of M0: install the eBPF + Go toolchain inside the Lima Ubuntu VM,
# generate bpf/vmlinux.h, and run the warm-up checks from the spec (§8).
# Run as the normal Lima user (it uses sudo where needed). Safe to re-run.
#
#   scripts/setup-vm.sh           # install everything, then run checks
#   scripts/setup-vm.sh --check   # only run the checks
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Go version to install when the one on PATH is older than go.mod requires.
GO_VERSION="${GO_VERSION:-$(awk '/^go /{print $2; exit}' "$REPO_DIR/go.mod")}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mok\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "run this inside the Lima VM (on the Mac use scripts/setup-mac.sh)"
case "$(uname -m)" in
  aarch64) GOARCH=arm64 ;;
  x86_64)  GOARCH=amd64 ;;
  *) die "unsupported arch $(uname -m)" ;;
esac
LIBSSL="/usr/lib/$(uname -m)-linux-gnu/libssl.so.3"

# version_ge A B: true if version A >= B.
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

install_packages() {
  log "installing apt packages"
  sudo apt-get update -qq
  local tools="linux-tools-$(uname -r)"
  apt-cache show "$tools" >/dev/null 2>&1 || tools="linux-tools-generic"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    clang llvm libbpf-dev "$tools" linux-tools-common bpftrace \
    make curl jq ca-certificates python3 openssl libssl3 wrk
}

install_go() {
  local have=""
  command -v go >/dev/null 2>&1 && have="$(go env GOVERSION | sed 's/^go//')"
  if [[ -n "$have" ]] && version_ge "$have" "$GO_VERSION"; then
    log "go $have already satisfies go.mod ($GO_VERSION)"
    return
  fi
  log "installing go $GO_VERSION (found: ${have:-none})"
  local tarball="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  # /usr/local/bin is on PATH for login shells, `limactl shell`, and sudo's
  # secure_path, so `sudo go run ./cmd/agent` works without PATH tweaks.
  sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
  sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  hash -r
  log "installed $(go version)"
}

gen_vmlinux() {
  log "generating bpf/vmlinux.h from /sys/kernel/btf/vmlinux"
  mkdir -p "$REPO_DIR/bpf"
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$REPO_DIR/bpf/vmlinux.h"
}

go_deps() {
  log "downloading go modules"
  (cd "$REPO_DIR" && go mod download && go build ./...)
}

# bpftrace_probe PROG: attach PROG for ~1s; success means the kernel accepted it.
bpftrace_probe() { sudo timeout 20 bpftrace -q -e "$1 interval:s:1 { exit(); }" >/dev/null 2>&1; }

run_checks() {
  FAILED=0
  log "checks"
  [[ -r /sys/kernel/btf/vmlinux ]]   && ok "kernel BTF present ($(uname -r))" || bad "no /sys/kernel/btf/vmlinux"
  command -v clang >/dev/null        && ok "$(clang --version | head -1)"      || bad "clang missing"
  command -v llvm-strip >/dev/null   && ok "llvm-strip present"                || bad "llvm-strip missing (bpf2go needs it)"
  [[ -r /usr/include/bpf/bpf_helpers.h ]] && ok "libbpf headers present"       || bad "libbpf-dev headers missing"
  bpftool version >/dev/null 2>&1    && ok "$(bpftool version | head -1)"      || bad "bpftool not working"
  [[ -s "$REPO_DIR/bpf/vmlinux.h" ]] && ok "bpf/vmlinux.h ($(wc -l < "$REPO_DIR/bpf/vmlinux.h") lines)" || bad "bpf/vmlinux.h missing"
  command -v go >/dev/null           && ok "$(go version)"                     || bad "go missing"
  (cd "$REPO_DIR" && go tool bpf2go -h >/dev/null 2>&1) && ok "bpf2go runs (go tool bpf2go)" || bad "bpf2go not runnable"
  (cd "$REPO_DIR" && go build -o /dev/null ./testserver) && ok "testserver builds" || bad "testserver build failed"
  bpftrace_probe 'kfunc:tcp_recvmsg { @ = count(); }' \
    && ok "fentry attaches to tcp_recvmsg (M1)" || bad "fentry on tcp_recvmsg failed (fallback: kprobes, spec §9)"
  if [[ -e "$LIBSSL" ]]; then
    bpftrace_probe "uretprobe:$LIBSSL:SSL_read { @ = count(); }" \
      && ok "uretprobe attaches to SSL_read (M3)" || bad "uretprobe on SSL_read failed"
  else
    bad "$LIBSSL not found"
  fi
  if [[ "$FAILED" == 0 ]]; then
    log "environment ready. Try: go run ./testserver  &&  curl localhost:8080/"
  else
    die "some checks failed"
  fi
}

if [[ "${1:-}" != "--check" ]]; then
  install_packages
  install_go
  gen_vmlinux
  go_deps
fi
run_checks
