package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/ebpf"
	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/k8s"
	"github.com/Tracewolff/Tracewulf-agent/pkg/tui"
)

func main() {
	interactive := term.IsTerminal(int(os.Stdout.Fd()))

	podCache := k8s.NewCache()
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if !interactive {
		// No TTY (e.g. running as a container without one attached) —
		// the TUI can't render, fall back to plain log lines.
		go func() {
			log.Println("connecting to Kubernetes API and syncing informers...")
			if err := k8s.StartInformer(podCache, stopCh); err != nil {
				errCh <- err
				return
			}
			log.Println("Kubernetes informers synced")

			report := func(stage string) {
				switch stage {
				case "ebpf":
					log.Println("eBPF programs loaded, kernel probes attached")
				case "dashboard":
					log.Println("dashboard listening on http://0.0.0.0:9090")
				}
			}
			errCh <- ebpf.Start(podCache, stopCh, report)
		}()

		select {
		case sig := <-sigCh:
			log.Printf("received signal %v, shutting down...", sig)
			close(stopCh)
			<-errCh
		case err := <-errCh:
			if err != nil {
				log.Fatalf("daemon exited with error: %v", err)
			}
		}
		return
	}

	reporter := tui.NewReporter()
	model := tui.NewModel(reporter)
	program := tea.NewProgram(model)

	go func() {
		reporter.Start(0)
		if err := k8s.StartInformer(podCache, stopCh); err != nil {
			reporter.Fail(0, err)
			errCh <- err
			return
		}
		reporter.Done(0, "synced")
		reporter.Start(1)

		report := func(stage string) {
			switch stage {
			case "ebpf":
				reporter.Done(1, "4 probes attached")
				reporter.Start(2)
			case "dashboard":
				reporter.Done(2, "")
				reporter.Ready("http://localhost:9090")
			}
		}

		errCh <- ebpf.Start(podCache, stopCh, report)
	}()

	go func() {
		<-sigCh
		close(stopCh)
		reporter.Quit()
	}()

	if _, err := program.Run(); err != nil {
		log.Println("tui error:", err)
	}

	if err := <-errCh; err != nil {
		log.Fatalf("daemon exited with error: %v", err)
	}
}
