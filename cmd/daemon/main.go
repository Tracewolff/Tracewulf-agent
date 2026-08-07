package main

import (
    "log"

    "github.com/Tracewolff/Tracewulf-agent/pkg/adapters/ebpf"
)

func main() {

	if err := ebpf.Start(); err != nil {
		log.Fatal(err)
	}

}