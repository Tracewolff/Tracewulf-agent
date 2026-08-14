package main

import (
	"log"

	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/ebpf"
	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/k8s"
)

func main() {
	podCache := k8s.NewCache()
	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := k8s.StartInformer(podCache, stopCh); err != nil {
		log.Fatalf("failed to start k8s informer: %v", err)
	}

	log.Println("Kubernetes Pod informer synced")

	if err := ebpf.Start(podCache); err != nil {
		log.Fatal(err)
	}
}
