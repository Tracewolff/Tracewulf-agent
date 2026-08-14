package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/ebpf"
	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/k8s"
)

func main() {
	podCache := k8s.NewCache()
	stopCh := make(chan struct{})

	if err := k8s.StartInformer(podCache, stopCh); err != nil {
		log.Fatalf("failed to start k8s informer: %v", err)
	}
	log.Println("Kubernetes Pod informer synced")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- ebpf.Start(podCache, stopCh)
	}()

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down...", sig)
		close(stopCh)
	case err := <-errCh:
		if err != nil {
			log.Fatalf("daemon exited with error: %v", err)
		}
	}
}
