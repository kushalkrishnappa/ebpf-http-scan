#!/usr/bin/env bash
# Host side of M0: install Lima and bring up the Ubuntu 24.04 VM.
# Safe to re-run: skips steps that are already done.
#
#   scripts/setup-mac.sh            # create/start the VM named "ebpf"
#   VM_NAME=foo scripts/setup-mac.sh
set -euo pipefail

VM_NAME="${VM_NAME:-ebpf}"
TEMPLATE="${TEMPLATE:-template://ubuntu-24.04}"
VM_CPUS="${VM_CPUS:-4}"
VM_MEMORY="${VM_MEMORY:-4}"   # GiB

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "run this on the Mac host (inside the VM use scripts/setup-vm.sh)"

if ! command -v limactl >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || die "Homebrew is required: https://brew.sh"
  log "installing lima"
  brew install lima
fi
log "lima: $(limactl --version)"

# `limactl list -q` prints one VM name per line.
if limactl list -q 2>/dev/null | grep -qx "$VM_NAME"; then
  status="$(limactl list --format '{{.Status}}' "$VM_NAME")"
  if [[ "$status" == "Running" ]]; then
    log "VM '$VM_NAME' already running"
  else
    log "starting existing VM '$VM_NAME' ($status)"
    limactl start "$VM_NAME"
  fi
else
  # --mount-writable: the home dir is mounted read-write so the VM can run
  # go generate / write vmlinux.h into this repo directly.
  log "creating VM '$VM_NAME' from $TEMPLATE (${VM_CPUS} CPUs, ${VM_MEMORY} GiB)"
  limactl start --name="$VM_NAME" --tty=false \
    --cpus="$VM_CPUS" --memory="$VM_MEMORY" \
    --mount-writable "$TEMPLATE"
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log "kernel in VM: $(limactl shell "$VM_NAME" uname -r)"
cat <<EOF

Next, install the toolchain inside the VM:

  limactl shell --workdir "$REPO_DIR" $VM_NAME ./scripts/setup-vm.sh

EOF
