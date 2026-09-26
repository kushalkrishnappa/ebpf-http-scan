package capture

// Compiles bpf/capture.bpf.c and generates capture_bpfel.go (+ .o). Run on
// Linux after scripts/setup-vm.sh has produced bpf/vmlinux.h.
//go:generate go tool bpf2go -tags linux -target bpfel -type event capture ../../bpf/capture.bpf.c -- -O2 -g -Wall -I../../bpf
