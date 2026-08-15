#!/usr/bin/env bash
#
# benchmark.sh — measure TraceWulf daemon overhead (idle vs under synthetic load)
#
# Usage:
#   sudo ./benchmark.sh [daemon_binary_path] [duration_seconds]
#
# Example:
#   sudo ./benchmark.sh ./tracewulf-bin 30
#
# Requires: pidstat (sysstat package), the compiled daemon binary, root (for eBPF)
#
set -euo pipefail

DAEMON_CMD="${1:-./tracewulf-bin}"
DURATION="${2:-30}"
LOG_DIR="$(mktemp -d)"
IDLE_LOG="${LOG_DIR}/idle.log"
LOAD_LOG="${LOG_DIR}/load.log"

# Pull out just the binary name (last path component) so pgrep can find it
# regardless of "sudo KUBECONFIG=... ./tracewulf-bin" style prefixes.
BIN_NAME="$(basename "$(echo "$DAEMON_CMD" | awk '{print $NF}')")"

command -v pidstat >/dev/null 2>&1 || {
    echo "pidstat not found. Install with: sudo apt install sysstat"
    exit 1
}

echo "== TraceWulf overhead benchmark =="
echo "Command : $DAEMON_CMD"
echo "Binary  : $BIN_NAME"
echo "Duration: ${DURATION}s per phase"
echo "Logs    : $LOG_DIR"
echo

# --- Start daemon ---
echo "[1/4] Starting daemon..."
eval "$DAEMON_CMD" &
EVAL_PID=$!

# Wait for the actual binary to appear (up to 10s), since $! may be a
# bash/sudo wrapper PID rather than the real process.
DAEMON_PID=""
for i in $(seq 1 20); do
    # -x matches the exact process name (comm), not the full command line —
    # avoids matching this very script's own args which also contain BIN_NAME.
    DAEMON_PID="$(pgrep -x "$BIN_NAME" | head -n1 || true)"
    if [ -n "$DAEMON_PID" ]; then
        break
    fi
    sleep 0.5
done

if [ -z "$DAEMON_PID" ]; then
    echo "Could not find running process matching '$BIN_NAME'. Is the binary name correct?"
    kill "$EVAL_PID" 2>/dev/null || true
    exit 1
fi

echo "Daemon PID: $DAEMON_PID (resolved via pgrep -f $BIN_NAME)"
ps -p "$DAEMON_PID" -o pid,cmd --no-headers

echo "Waiting 3s more for full init (eBPF attach, informer sync, HTTP listen)..."
sleep 3

# --- Phase 1: idle ---
echo "[2/4] Measuring IDLE overhead for ${DURATION}s (no synthetic traffic)..."
pidstat -p "$DAEMON_PID" 1 "$DURATION" > "$IDLE_LOG"

# --- Phase 2: load ---
echo "[3/4] Generating synthetic traffic + measuring LOAD overhead for ${DURATION}s..."
(
    END=$((SECONDS + DURATION))
    while [ $SECONDS -lt $END ]; do
        curl -s -o /dev/null http://127.0.0.1:9090/ || true
        /bin/true   # cheap execve() event for the tracer to catch
        sleep 0.05
    done
) &
LOADGEN_PID=$!

pidstat -p "$DAEMON_PID" 1 "$DURATION" > "$LOAD_LOG"
wait "$LOADGEN_PID" 2>/dev/null || true

# --- Cleanup ---
echo "[4/4] Stopping daemon..."
kill "$DAEMON_PID" 2>/dev/null || true
kill "$EVAL_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
wait "$EVAL_PID" 2>/dev/null || true

# --- Summarize ---
summarize() {
    local file="$1"
    local label="$2"
    awk -v label="$label" '
        /Average/ { next }
        /%CPU/ { next }
        NF > 7 && $1 ~ /^[0-9]/ {
            count++
            sum += $(NF-2)
            if ($(NF-2) > max) max = $(NF-2)
        }
        END {
            if (count > 0) {
                printf "%s: avg CPU = %.2f%%, peak CPU = %.2f%% (n=%d samples)\n", label, sum/count, max, count
            } else {
                printf "%s: no samples captured\n", label
            }
        }
    ' "$file"
}

echo
echo "== RESULTS =="
summarize "$IDLE_LOG" "IDLE"
summarize "$LOAD_LOG" "LOAD"
echo
echo "Raw logs kept at: $LOG_DIR"
echo "(For RAM/RSS too, re-run pidstat manually with: pidstat -r -p $DAEMON_PID 1 $DURATION)"