<p align="center">
  <img src="Screenshot 2026-08-16 152230.png" width="684" height="565" alt="High-Level Architecture diagram of TraceWulf" />
</p>
<div align="center">

# 🐺 TraceWulf

**See what's actually crossing your availability zones — before the bill tells you.**

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-client--go-326CE5?logo=kubernetes&logoColor=white)
![eBPF](https://img.shields.io/badge/eBPF-cilium%2Febpf-orange)
![Status](https://img.shields.io/badge/status-alpha-yellow)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

TraceWulf is a **network cost observability agent** that attaches directly to the Linux kernel via eBPF to trace TCP connections and byte-level data transfer between Kubernetes workloads, resolves every flow into Kubernetes identity, and estimates cross-availability-zone cost in real time.

Instead of waiting on a monthly cloud bill or correlating VPC Flow Logs against billing exports by hand, TraceWulf tells you — as it happens — which Pod is talking to which Service, whether that traffic crosses a zone boundary, and roughly what it costs.

Built for **Platform Engineers**, **SREs**, and anyone operating multi-AZ Kubernetes who has ever been surprised by a network line item.

## Table of Contents

- [Why TraceWulf?](#why-tracewulf)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Core Capabilities](#core-capabilities)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [High-Level Architecture](#high-level-architecture)
- [Design Principles](#design-principles)
- [Cost Model](#cost-model)
- [Why not just VPC Flow Logs?](#why-not-just-vpc-flow-logs)
- [Performance](#performance)
- [Status](#status)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Why TraceWulf?

Kubernetes makes it trivial to spread workloads across nodes and zones for resilience — and just as trivial to accidentally route a hot path across an availability-zone boundary, where every gigabyte has a price. Nothing in a standard cluster tells you this is happening while it's happening.

## The Problem

Cross-AZ and egress network costs are usually invisible until they show up as a line item on the monthly cloud bill, by which point the traffic pattern that caused them may have been running for weeks.

The common ways to get visibility today are indirect:
- **VPC Flow Logs + billing exports** — accurate eventually, but delayed by minutes, and the flow logs themselves cost money to collect and store.
- **Service mesh telemetry** — accurate and real-time, but requires adopting a full mesh (Istio/Linkerd) with sidecars in every Pod, just to get network visibility as a side effect.
- **Manual correlation** — cross-referencing `kubectl get pods -o wide` against node zone labels and traffic guesses. Slow, error-prone, and doesn't scale past a handful of services.

None of these give an operator a live answer to: *"Right now, which workloads are generating cross-zone traffic, and roughly what is it costing?"*

## The Solution

TraceWulf reads the kernel directly. `execve`, `tcp_v4_connect`, `tcp_sendmsg`, and `tcp_recvmsg` are traced via eBPF kprobes and kretprobes, streamed through a ring buffer into userspace, and immediately resolved against live Kubernetes API state — Pod, Service, Node, and Zone.

A flow is only ever marked cross-AZ, and only ever costed, when both endpoints resolve to a **known** zone. Nothing is inferred or guessed. The result streams to a live dashboard and is persisted so cumulative cost survives a restart — all with nothing installed in the workloads being observed.

## Core Capabilities

- Zero-instrumentation TCP connection and byte-transfer tracing via eBPF
- Kubernetes-aware flow resolution — Pod, Service, Node, and Zone, not raw IPs
- Cross-AZ detection and cost estimation, computed only from confirmed zone data
- Durable history — cumulative traffic and cost survive daemon restarts
- Built-in live dashboard, no Prometheus/Grafana required to get started
- Bounded memory and batched aggregation instead of raw per-event streaming

## Installation

> A container image and Helm chart are in progress. For now, TraceWulf runs from source.

### From source

git clone [https://github.com/Tracewolff/Tracewulf-agent.git](https://github.com/Tracewolff/Tracewulf-agent.git)
cd Tracewulf-agent
go generate ./...
go build ./...

Requires a Linux host with kernel 5.8+ and BTF support (`/sys/kernel/btf/vmlinux` present), Go 1.22+, and clang for the eBPF build step.

## Quick Start

sudo -E ./tracewulf

kubernetes informer synced
ebpf probes attached (4)
dashboard listening on [http://0.0.0.0:9090](http://0.0.0.0:9090)
[TCP][cross-az] checkout-service (us-east-1a) -> pricing-svc (us-east-1b)  cost=$0.00011

Open `http://localhost:9090` for the live dashboard — current flows, cumulative session cost, and a recent-intervals trend view.

## High-Level Architecture
<img width="684" height="565" alt="image" src="https://github.com/user-attachments/assets/9cd4b665-63da-443c-a602-4a668f4c3120" />

## Design Principles

| Principle | Description |
|---|---|
| **Zero instrumentation** | No sidecars, no code changes, no service mesh. Observation happens entirely at the kernel boundary. |
| **Never guess identity** | A flow is only attributed to a Pod, Service, or Zone when the Kubernetes API confirms it. Unresolvable IPs are reported as-is. |
| **Bill like the cloud does** | Only egress (`tcp_sendmsg`) is counted toward cost, matching how providers actually charge — avoids double-counting a transfer from both the sender's and receiver's side. |
| **Bounded memory, always** | The in-memory aggregator resets on a fixed interval; history keeps a capped ring buffer regardless of daemon uptime. |
| **Low overhead by construction** | Kernel-side filtering and batched aggregation instead of raw per-event streaming — not an afterthought bolted on later. |

## Cost Model
cost_usd = (egress_bytes / 10^9) * cost_per_gb


Applied only to flows where both endpoints resolve to a known Node with a known, differing zone label. Default rate is `$0.01/GB`, configurable via `TRACEWULF_COST_PER_GB`. This is an estimate from application-layer byte counts, not wire-level bytes — actual cloud billing may differ slightly due to protocol overhead, and has not yet been validated against a real cloud bill.

## Why not just VPC Flow Logs?

| Capability | VPC Flow Logs + billing | Service mesh | TraceWulf |
|---|:---:|:---:|:---:|
| Real-time (seconds, not minutes) | ❌ | ✅ | ✅ |
| No extra cost to collect | ❌ | — | ✅ |
| No code/sidecar changes | ✅ | ❌ | ✅ |
| Kubernetes identity (Pod/Service/Zone) | ❌ | ✅ | ✅ |
| Cross-AZ cost estimate | manual | manual | ✅ |

## Performance

Measured locally with `pidstat`, idle vs. synthetic load:

| | CPU (avg) | CPU (peak) | RSS |
|---|---|---|---|
| Idle | 0.40% | 2.00% | ~79 MB |
| Under load | 3.53% | 5.00% | ~79 MB |

Not yet benchmarked side-by-side against other observability agents on identical hardware — that comparison is on the roadmap.

## Status

TraceWulf is **alpha**, under active development, validated so far on a multi-node Minikube cluster with manually labeled zones. Before this is production-usable:

- [ ] No authentication on the dashboard endpoint
- [ ] Not yet packaged for deployment (Docker image / Helm chart in progress)
- [ ] Not yet validated against real AWS cross-AZ billing
- [ ] No automated test suite yet

## Documentation

Full documentation is in progress.

| Document | Description |
|---|---|
| Architecture | Detailed system architecture and execution flow — coming soon |
| Deployment guide | Helm chart and DaemonSet deployment — coming soon |
| Cost model reference | Full configuration and cost calculation reference — coming soon |

## Contributing

Issues and pull requests are welcome. This project is early-stage — expect the internals to move quickly.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.
EOF
