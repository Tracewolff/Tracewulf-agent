package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -I../../../bpf -I../../../bpf/headers" tracer ../../../bpf/tracer.bpf.c
