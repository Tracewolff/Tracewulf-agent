BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall

generate:
	go generate ./...

clean:
	rm -f pkg/adapters/ebpf/*.o
	rm -f pkg/adapters/ebpf/*.go