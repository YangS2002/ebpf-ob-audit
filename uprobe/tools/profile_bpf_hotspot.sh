#!/usr/bin/env bash
# 在 OB 节点采样 uprobe BPF 程序的 CPU 热点。
# 用法: sudo ./profile_bpf_hotspot.sh [duration_sec]
# 需要: perf, bpftool(/usr/sbin), 已加载 handle_uprobe 且 observer 有负载。
set -u
DUR="${1:-30}"
BPFTOOL=/usr/sbin/bpftool
OUT=/tmp/bpf_hotspot_$(date +%H%M%S)
mkdir -p "$OUT"

PROG_ID=$($BPFTOOL prog show 2>/dev/null | awk '/name handle_uprobe/{sub(":","",$1);print $1;exit}')
if [ -z "$PROG_ID" ]; then echo "handle_uprobe prog not found"; exit 1; fi
echo "prog_id=$PROG_ID duration=${DUR}s out=$OUT"

# 1) 单 prog 周期/指令 (每次调用均值)
( $BPFTOOL prog profile id "$PROG_ID" duration "$DUR" cycles instructions > "$OUT/prog_profile.txt" 2>&1 ) &
PP=$!

# 2) 系统级采样火焰数据
perf record -F 299 -a -g -o "$OUT/perf.data" -- sleep $((DUR+2)) >/dev/null 2>&1
wait $PP 2>/dev/null

# 3) 文本报告: 按符号聚合 (关注 copy_from_user_nofault / bpf_prog_*handle_uprobe / ringbuf)
perf report -i "$OUT/perf.data" --stdio -g none --percent-limit 0.5 > "$OUT/perf_by_symbol.txt" 2>/dev/null
# 4) 调用图报告 (谁调用了这些开销)
perf report -i "$OUT/perf.data" --stdio --percent-limit 1 > "$OUT/perf_callgraph.txt" 2>/dev/null

echo "=== prog_profile.txt ==="; cat "$OUT/prog_profile.txt"
echo; echo "=== top symbols (uprobe/bpf/copy related) ==="
grep -iE 'handle_uprobe|copy_from_user|bpf_prog|ringbuf|__bpf|probe_read|observer' "$OUT/perf_by_symbol.txt" | head -40
echo; echo "full reports in $OUT/"
