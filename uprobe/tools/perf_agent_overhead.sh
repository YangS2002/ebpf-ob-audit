#!/usr/bin/env bash
# perf_agent_overhead.sh
# Measure runtime CPU/overhead of the uprobe agent (consumer side) with perf,
# and produce a flamegraph for hot-path attribution.
#
# Prereqs on target host (e.g. 7.27.222.3):
#   - perf installed
#   - agent binary built with `-g -fno-omit-frame-pointer` (frame-pointer stacks)
#   - run as root (agent runs under sudo); script re-execs perf with sudo if needed
#
# Usage:
#   ./perf_agent_overhead.sh [-d SECONDS] [-f HZ] [-p PID] [-l AGENT_LOG] [-o OUTDIR]
#
#   -d  sample duration seconds        (default 30)
#   -f  perf sampling frequency Hz     (default 99; use 999 for finer stacks)
#   -p  target PID                     (default: auto-detect `bin/uprobe`)
#   -l  agent.log path                 (optional: capture loss-metric delta)
#   -o  output directory               (default ./perf_agent_<ts>)
#
# Optional env:
#   FLAMEGRAPH_DIR=/path/to/FlameGraph  (dir containing stackcollapse-perf.pl + flamegraph.pl)

set -euo pipefail

DURATION=30
FREQ=99
PID=""
AGENT_LOG=""
OUTDIR=""

while getopts "d:f:p:l:o:h" opt; do
  case "$opt" in
    d) DURATION="$OPTARG" ;;
    f) FREQ="$OPTARG" ;;
    p) PID="$OPTARG" ;;
    l) AGENT_LOG="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "bad option; use -h" >&2; exit 2 ;;
  esac
done

# ---- privilege: perf on a root-owned process needs root ----
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    echo "WARN: not root and no sudo; perf may fail on root-owned agent" >&2
  fi
fi

command -v perf >/dev/null 2>&1 || { echo "ERROR: perf not found in PATH" >&2; exit 1; }

# ---- locate agent PID ----
if [ -z "$PID" ]; then
  PID="$(pgrep -f 'bin/uprobe' | head -n1 || true)"
  [ -z "$PID" ] && PID="$(pgrep -x uprobe | head -n1 || true)"
fi
if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
  echo "ERROR: uprobe agent process not found. Start the agent first, or pass -p PID." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
[ -z "$OUTDIR" ] && OUTDIR="./perf_agent_${TS}"
mkdir -p "$OUTDIR"

echo "=== perf agent overhead ==="
echo "PID       : $PID"
echo "cmdline   : $(tr '\0' ' ' < /proc/$PID/cmdline)"
echo "duration  : ${DURATION}s   freq: ${FREQ}Hz"
echo "outdir    : $OUTDIR"
echo

# ---- snapshot: threads (name + tid) ----
{
  echo "# thread snapshot @ start"
  ps -L -o tid,pcpu,comm -p "$PID" 2>/dev/null || true
} | tee "$OUTDIR/threads_start.txt"
echo

# ---- optional: agent.log loss-metric BEFORE ----
if [ -n "$AGENT_LOG" ] && [ -f "$AGENT_LOG" ]; then
  grep -E 'event=agent_(loss_metrics|audit_accounting|metrics)' "$AGENT_LOG" 2>/dev/null | tail -n1 \
    > "$OUTDIR/agent_log_before.txt" || true
fi

# ---- launch background samplers ----
# per-thread CPU (main vs worker breakdown), 1s interval
( pidstat -t -p "$PID" -h -u 1 "$DURATION" > "$OUTDIR/pidstat_threads.txt" 2>&1 ) &
PIDSTAT_PID=$!
# process-level CPU+mem+ctxt switches
( pidstat -p "$PID" -h -r -w -u 1 "$DURATION" > "$OUTDIR/pidstat_proc.txt" 2>&1 ) &
PIDSTAT2_PID=$!
# system-wide per-CPU utilization (context: is host CPU-bound?)
( mpstat -P ALL 1 "$DURATION" > "$OUTDIR/mpstat.txt" 2>&1 ) &
MPSTAT_PID=$!

# ---- perf stat: hardware/software counters (whole process, all threads) ----
$SUDO perf stat -p "$PID" \
  -e task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,branches,branch-misses \
  -- sleep "$DURATION" 2> "$OUTDIR/perf_stat.txt" &
STAT_PID=$!

# ---- perf record: call-graph via frame pointers ----
echo "recording call-graph (fp) for ${DURATION}s ..."
$SUDO perf record -g --call-graph fp -F "$FREQ" -p "$PID" -o "$OUTDIR/perf.data" -- sleep "$DURATION" \
  2> "$OUTDIR/perf_record.log" || {
    echo "perf record failed; see $OUTDIR/perf_record.log" >&2
  }

wait "$STAT_PID" 2>/dev/null || true
wait "$PIDSTAT_PID" "$PIDSTAT2_PID" "$MPSTAT_PID" 2>/dev/null || true

# make perf.data readable without sudo downstream
[ -n "$SUDO" ] && $SUDO chown "$(id -u):$(id -g)" "$OUTDIR/perf.data" 2>/dev/null || true

# ---- agent.log loss-metric AFTER ----
if [ -n "$AGENT_LOG" ] && [ -f "$AGENT_LOG" ]; then
  grep -E 'event=agent_(loss_metrics|audit_accounting|metrics)' "$AGENT_LOG" 2>/dev/null | tail -n1 \
    > "$OUTDIR/agent_log_after.txt" || true
fi

# ---- text report: top functions (self time) ----
if [ -s "$OUTDIR/perf.data" ]; then
  perf report -i "$OUTDIR/perf.data" --stdio --percent-limit 0.5 -n \
    > "$OUTDIR/perf_report.txt" 2>/dev/null || true
  # callgraph text (who calls the hot fns)
  perf report -i "$OUTDIR/perf.data" --stdio -g graph,0.5,caller \
    > "$OUTDIR/perf_report_callgraph.txt" 2>/dev/null || true
fi

# ---- flamegraph ----
FG_DIR=""
if [ -n "${FLAMEGRAPH_DIR:-}" ] && [ -f "$FLAMEGRAPH_DIR/flamegraph.pl" ]; then
  FG_DIR="$FLAMEGRAPH_DIR"
elif command -v flamegraph.pl >/dev/null 2>&1 && command -v stackcollapse-perf.pl >/dev/null 2>&1; then
  FG_DIR="$(dirname "$(command -v flamegraph.pl)")"
elif [ -f /usr/share/flamegraph/flamegraph.pl ]; then
  FG_DIR=/usr/share/flamegraph
fi

if [ -s "$OUTDIR/perf.data" ]; then
  perf script -i "$OUTDIR/perf.data" > "$OUTDIR/perf.script" 2>/dev/null || true
fi

if [ -n "$FG_DIR" ] && [ -s "$OUTDIR/perf.script" ]; then
  COLLAPSE="$FG_DIR/stackcollapse-perf.pl"; [ -x "$COLLAPSE" ] || COLLAPSE="perl $COLLAPSE"
  FLAME="$FG_DIR/flamegraph.pl"; [ -x "$FLAME" ] || FLAME="perl $FLAME"
  $COLLAPSE "$OUTDIR/perf.script" > "$OUTDIR/out.folded" 2>/dev/null || true
  $FLAME --title "uprobe agent CPU (PID $PID, ${DURATION}s)" "$OUTDIR/out.folded" \
    > "$OUTDIR/flamegraph.svg" 2>/dev/null || true
  [ -s "$OUTDIR/flamegraph.svg" ] && echo "flamegraph -> $OUTDIR/flamegraph.svg"
else
  echo "NOTE: FlameGraph scripts not found; SVG skipped."
  echo "      perf.script saved. To render later:"
  echo "        git clone https://github.com/brendangregg/FlameGraph"
  echo "        FlameGraph/stackcollapse-perf.pl $OUTDIR/perf.script > out.folded"
  echo "        FlameGraph/flamegraph.pl out.folded > flamegraph.svg"
fi

# ---- summary ----
echo
echo "================ SUMMARY ================"
echo "--- perf stat (process, ${DURATION}s) ---"
cat "$OUTDIR/perf_stat.txt" 2>/dev/null || true
echo
echo "--- top self-time functions ---"
[ -f "$OUTDIR/perf_report.txt" ] && grep -vE '^#|^$' "$OUTDIR/perf_report.txt" | head -n 20 || true
echo
echo "--- agent.log loss delta ---"
[ -f "$OUTDIR/agent_log_before.txt" ] && echo "before: $(cat "$OUTDIR/agent_log_before.txt")"
[ -f "$OUTDIR/agent_log_after.txt" ]  && echo "after : $(cat "$OUTDIR/agent_log_after.txt")"
echo
echo "artifacts in: $OUTDIR"
echo "  perf.data / perf.script / out.folded / flamegraph.svg"
echo "  perf_stat.txt / perf_report.txt / perf_report_callgraph.txt"
echo "  pidstat_threads.txt / pidstat_proc.txt / mpstat.txt"
echo "========================================="
