#!/usr/bin/env bash
# perf_bpf_overhead.sh
# Measure eBPF-side overhead of the audit uprobe program. The BPF cost is charged
# to the traced process (OB observer), NOT the agent. Two measurements:
#   (1) pure BPF program exec time  -> kernel.bpf_stats_enabled + agent fdinfo
#       (run_time_ns / run_cnt over the window; bpftool not required)
#   (2) full uprobe trap path cost on the observer -> perf record -g on observer PID
#       (kernel-side frames resolve via kallsyms regardless of observer frame pointers)
#
# Usage:
#   ./perf_bpf_overhead.sh [-d SEC] [-f HZ] [-O observer_pid] [-A agent_pid] [-o OUTDIR]
#     -d duration sec           (default 30)
#     -f perf freq Hz           (default 999)
#     -O observer PID           (default: pgrep -x observer)
#     -A agent PID              (default: pgrep -f bin/uprobe)
#     -o output dir             (default ./perf_bpf_<ts>)
# Optional env: FLAMEGRAPH_DIR=/path/to/FlameGraph
# Must run as root (needs bpf_stats + perf on foreign PID).

set -euo pipefail
DURATION=30; FREQ=999; OBS=""; AGENT=""; OUTDIR=""
while getopts "d:f:O:A:o:h" opt; do case "$opt" in
  d) DURATION="$OPTARG";; f) FREQ="$OPTARG";; O) OBS="$OPTARG";;
  A) AGENT="$OPTARG";; o) OUTDIR="$OPTARG";;
  h) grep '^#' "$0" | sed 's/^# \?//'; exit 0;; *) exit 2;; esac; done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo)"; exit 1; }
command -v perf >/dev/null || { echo "ERROR: perf not found"; exit 1; }

[ -z "$OBS" ]   && OBS="$(pgrep -x observer | head -n1 || true)"
[ -z "$AGENT" ] && AGENT="$(pgrep -f 'bin/uprobe' | head -n1 || true)"
[ -z "$OBS" ]   && { echo "ERROR: observer PID not found (-O)"; exit 1; }
[ -d "/proc/$OBS" ] || { echo "ERROR: observer PID $OBS gone"; exit 1; }

TS="$(date +%Y%m%d_%H%M%S)"; [ -z "$OUTDIR" ] && OUTDIR="./perf_bpf_${TS}"; mkdir -p "$OUTDIR"
echo "=== eBPF overhead monitor ==="
echo "observer PID: $OBS   agent PID: ${AGENT:-<none>}   dur:${DURATION}s freq:${FREQ}Hz"
echo "outdir: $OUTDIR"; echo

# ---- (1) enable BPF run-stats, snapshot agent prog fdinfo ----
PRIOR_STATS="$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo 0)"
echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo "WARN: cannot enable bpf_stats" >&2

# dump helper: for each bpf-prog fd of AGENT, print "progid run_time_ns run_cnt"
dump_prog_stats() {
  local pid="$1"
  [ -z "$pid" ] && return 0
  local fd id rt rc
  for fd in /proc/$pid/fdinfo/*; do
    [ -f "$fd" ] || continue
    grep -q '^prog_type:' "$fd" 2>/dev/null || continue
    id="$(sed -n 's/^prog_id:\s*//p' "$fd")"
    rt="$(sed -n 's/^run_time_ns:\s*//p' "$fd")"
    rc="$(sed -n 's/^run_cnt:\s*//p' "$fd")"
    [ -n "$rt" ] && echo "$id ${rt:-0} ${rc:-0}"
  done
}

dump_prog_stats "$AGENT" > "$OUTDIR/bpf_stats_before.txt" || true

# ---- background samplers on observer ----
( pidstat -p "$OBS" -h -u 1 "$DURATION" > "$OUTDIR/pidstat_observer.txt" 2>&1 ) &
P1=$!

# perf stat on observer whole process
perf stat -p "$OBS" -e task-clock,context-switches,cpu-migrations,minor-faults \
  -- sleep "$DURATION" 2> "$OUTDIR/perf_stat_observer.txt" &
S1=$!

# perf record on observer (kernel call-graph = uprobe trap path)
echo "recording observer uprobe path for ${DURATION}s ..."
perf record -g --call-graph fp -F "$FREQ" -p "$OBS" -o "$OUTDIR/perf.data" -- sleep "$DURATION" \
  2> "$OUTDIR/perf_record.log" || echo "perf record failed; see log" >&2

wait "$S1" 2>/dev/null || true
wait "$P1" 2>/dev/null || true

dump_prog_stats "$AGENT" > "$OUTDIR/bpf_stats_after.txt" || true

# restore stats toggle
echo "$PRIOR_STATS" > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || true

# ---- compute pure BPF exec cost ----
python3 - "$OUTDIR/bpf_stats_before.txt" "$OUTDIR/bpf_stats_after.txt" "$DURATION" \
  > "$OUTDIR/bpf_exec_summary.txt" 2>/dev/null <<'PY' || true
import sys
bef,aft,dur=sys.argv[1],sys.argv[2],float(sys.argv[3])
def load(p):
    d={}
    try:
        for l in open(p):
            a=l.split()
            if len(a)>=3: d[a[0]]=(int(a[1]),int(a[2]))
    except FileNotFoundError: pass
    return d
B,A=load(bef),load(aft)
win=dur*1e9
print(f"window: {dur:.0f}s")
tot_ns=tot_cnt=0
for pid in sorted(set(A)|set(B)):
    b=B.get(pid,(0,0)); a=A.get(pid,(0,0))
    dns=a[0]-b[0]; dcnt=a[1]-b[1]
    if dcnt<0 or dns<0: continue
    tot_ns+=dns; tot_cnt+=dcnt
    avg=(dns/dcnt) if dcnt else 0
    print(f"  prog_id={pid}: runs={dcnt}  run_time={dns/1e6:.2f}ms  avg={avg:.0f}ns/run  rate={dcnt/dur:.0f}/s")
if tot_cnt:
    print(f"TOTAL BPF: runs={tot_cnt} ({tot_cnt/dur:.0f}/s)  exec={tot_ns/1e6:.2f}ms  avg={tot_ns/tot_cnt:.0f}ns/run")
    print(f"BPF CPU share of ONE core: {100*tot_ns/win:.3f}%   (charged to observer threads)")
else:
    print("no BPF run delta captured (prog fds not found in agent, or stats off)")
PY

# ---- observer perf report: isolate uprobe/bpf frames ----
if [ -s "$OUTDIR/perf.data" ]; then
  perf report -i "$OUTDIR/perf.data" --stdio --percent-limit 0.3 -n \
    > "$OUTDIR/perf_report_observer.txt" 2>/dev/null || true
  perf script -i "$OUTDIR/perf.data" > "$OUTDIR/perf.script" 2>/dev/null || true
fi

# quantify uprobe-path share via folded stacks
FG_DIR=""
[ -n "${FLAMEGRAPH_DIR:-}" ] && [ -f "$FLAMEGRAPH_DIR/flamegraph.pl" ] && FG_DIR="$FLAMEGRAPH_DIR"
if [ -n "$FG_DIR" ] && [ -s "$OUTDIR/perf.script" ]; then
  perl "$FG_DIR/stackcollapse-perf.pl" "$OUTDIR/perf.script" > "$OUTDIR/out.folded" 2>/dev/null || true
  perl "$FG_DIR/flamegraph.pl" --title "OB observer CPU (uprobe path, PID $OBS)" \
    "$OUTDIR/out.folded" > "$OUTDIR/flamegraph_observer.svg" 2>/dev/null || true
  [ -s "$OUTDIR/flamegraph_observer.svg" ] && echo "flamegraph -> $OUTDIR/flamegraph_observer.svg"
fi

if [ -s "$OUTDIR/out.folded" ]; then
python3 - "$OUTDIR/out.folded" > "$OUTDIR/uprobe_path_share.txt" 2>/dev/null <<'PY' || true
import sys
tot=0; up=0
KEYS=('handle_swbp','uprobe','arch_uprobe','bpf_prog','trace_call_bpf','bpf_trace_run',
      'uprobe_notify_resume','send_sig','int3','do_int3','optimized_callback','kprobe')
for l in open(sys.argv[1]):
    s,c=l.rstrip().rsplit(' ',1); c=int(c); tot+=c
    ls=s.lower()
    if any(k in ls for k in KEYS): up+=c
if tot:
    print(f"observer on-CPU samples: {tot}")
    print(f"uprobe/BPF trap path share of observer on-CPU time: {100*up/tot:.2f}%")
PY
fi

echo
echo "================ SUMMARY ================"
echo "--- pure BPF program exec cost ---"; cat "$OUTDIR/bpf_exec_summary.txt" 2>/dev/null
echo; echo "--- uprobe path share of observer CPU ---"; cat "$OUTDIR/uprobe_path_share.txt" 2>/dev/null
echo; echo "--- observer perf stat ---"; cat "$OUTDIR/perf_stat_observer.txt" 2>/dev/null
echo; echo "artifacts in: $OUTDIR (perf.data, perf_report_observer.txt, flamegraph_observer.svg, bpf_stats_*.txt)"
echo "========================================="
