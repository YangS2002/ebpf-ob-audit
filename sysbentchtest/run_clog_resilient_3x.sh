#!/usr/bin/env bash
# 自动化 sysbench 压测编排脚本：clog hung 容错，必须跑满 N 次成功结果。
#
# 每一轮完整循环：
#   1. obd cluster start <CLUSTER>
#   2. 等待 OB 可连接
#   3. (可选) 启动 uprobe/eBPF agent
#   4. sysbench cleanup (保证干净) + prepare 灌数
#   5. sysbench run (带主机 + OB 指标监控)
#   6. (可选) 停 agent
#   7. obd cluster stop <CLUSTER>
#   8. (可选) 清空 MongoDB 审计集合
#
# clog hung 判定：prepare / run 阶段 sysbench 输出出现 FATAL/PANIC/WARNING/连接错误，
# 或超过超时无返回，即判为中断。中断后：sysbench cleanup 清空数据 -> (停 agent) ->
# obd cluster stop -> (清 mongo) -> 该次目录标记 -FAILED-* (指标保留, 不计成功) -> 重试。
#
# 直到累计 SUCCESS_TARGET(默认3) 次成功。每次成功指标独立目录, 互不覆盖。
#
# 用法:
#   ./run_clog_resilient_3x.sh
#   THREADS=256 TIME=1800 SUCCESS_TARGET=3 ./run_clog_resilient_3x.sh
#   # 测 uprobe+eBPF 采集链路对压测的影响:
#   WITH_AGENT=1 THREADS=256 TIME=1800 SESSION_ID=rw-256-uprobe-1800s ./run_clog_resilient_3x.sh
#
# 注意: 不使用 set -e, 失败路径由脚本显式处理并重试。

set -uo pipefail

# 根分区 / 可能已满, /tmp 无空间会导致 obd(PyInstaller) 解包失败:
#   "[PYI-...:ERROR] Could not create temporary directory!"
# 将临时目录指向有空间的分区 (可用 TMPDIR 覆盖)。
export TMPDIR="${TMPDIR:-/home/yangshuo17/tmp}"
mkdir -p "$TMPDIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_DIR="${MONITOR_DIR:-$SCRIPT_DIR}"

# ---------- 集群 / obd ----------
OBD="${OBD:-obd}"
CLUSTER="${CLUSTER:-ob3node}"

# ---------- 连接参数 (对齐 run_ob_rw_bench_with_monitor.sh) ----------
SSH_PORT="${SSH_PORT:-32200}"
SSH_USER="${SSH_USER:-yangshuo17}"
OB_NODES_CSV="${OB_NODES:-7.27.43.136,7.27.43.137,7.27.43.138}"
ODP_HOST="${ODP_HOST:-7.27.43.139}"
ODP_PORT="${ODP_PORT:-2883}"
SYS_HOST="${SYS_HOST:-7.27.43.136}"
SYS_PORT="${SYS_PORT:-2881}"
SYS_USER="${SYS_USER:-root@sys}"
SYS_PASSWORD="${SYS_PASSWORD:-oceanbase}"
MYSQL_USER="${MYSQL_USER:-root@perf#ob3node}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
MYSQL_DB="${MYSQL_DB:-sbtest}"

# ---------- sysbench 负载 ----------
SYSBENCH_LUA="${SYSBENCH_LUA:-/usr/share/sysbench/oltp_read_write.lua}"
TABLES="${TABLES:-30}"
TABLE_SIZE="${TABLE_SIZE:-1000000}"
THREADS="${THREADS:-256}"
TIME="${TIME:-1800}"
INTERVAL="${INTERVAL:-10}"
RAND_TYPE="${RAND_TYPE:-uniform}"
PREPARE_THREADS="${PREPARE_THREADS:-8}"

# ---------- 编排 / 容错 ----------
SUCCESS_TARGET="${SUCCESS_TARGET:-3}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
# OB 启动后等待可连接的最大秒数
OB_READY_TIMEOUT="${OB_READY_TIMEOUT:-300}"
# prepare 超时 (无返回视为 hung); run 超时给 TIME 留 600s 缓冲
PREPARE_TIMEOUT="${PREPARE_TIMEOUT:-3600}"
RUN_TIMEOUT="${RUN_TIMEOUT:-$((TIME + 600))}"
# clog hung 特征: sysbench 输出中的致命/告警/连接类关键字 (可覆盖)
HUNG_PATTERN="${HUNG_PATTERN:-FATAL|PANIC|WARNING|Lost connection|Cannot connect|failed to connect|Communication link failure|gone away|Deadlock found}"

# ---------- uprobe/eBPF agent + MongoDB (WITH_AGENT=1 开启, 用于测采集链路对压测的影响) ----------
WITH_AGENT="${WITH_AGENT:-0}"
REPO_DIR="${REPO_DIR:-/home/yangshuo17/ebpf-ob-audit}"
PYTHON="${PYTHON:-python3}"
AGENT_DEPLOY_YAML="${AGENT_DEPLOY_YAML:-$REPO_DIR/uprobe/deploy/agent-deploy.example.yaml}"
AGENT_START_ACTION="${AGENT_START_ACTION:-start}"   # agent 已部署时用 start; 未部署改 deploy-start
MONGO_CONTAINER="${MONGO_CONTAINER:-mongodb8}"
MONGO_URI="${MONGO_URI:-mongodb://audit_collector:1@7.27.43.145:27017/ob_audit?authSource=ob_audit}"
MONGO_DROP_EVAL="${MONGO_DROP_EVAL:-db.audit_events.drop()}"

# ---------- 日志目录 ----------
LOG_ROOT="${LOG_ROOT:-/home/yangshuo17/sysbentchtest}"
SESSION_ID="${SESSION_ID:-clog3x-$(date +%Y%m%d-%H%M%S)}"
SESSION_DIR="$LOG_ROOT/$SESSION_ID"
mkdir -p "$SESSION_DIR"
SESSION_LOG="$SESSION_DIR/session.log"
SUMMARY="$SESSION_DIR/summary.txt"

IFS=',' read -r -a OB_NODES <<< "$OB_NODES_CSV"
MONITOR_PIDS=()

mysql_perf_args=( -h"$ODP_HOST" -P"$ODP_PORT" -u"$MYSQL_USER" "--password=$MYSQL_PASSWORD" )
mysql_sys_args=(  -h"$SYS_HOST"  -P"$SYS_PORT"  -u"$SYS_USER"  "--password=$SYS_PASSWORD" )

sysbench_common=(
  "$SYSBENCH_LUA"
  --mysql-host="$ODP_HOST"
  --mysql-port="$ODP_PORT"
  --mysql-user="$MYSQL_USER"
  --mysql-password="$MYSQL_PASSWORD"
  --mysql-db="$MYSQL_DB"
  --db-driver=mysql
  --db-ps-mode=disable
  --tables="$TABLES"
  --table-size="$TABLE_SIZE"
)

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SESSION_LOG"
}

# ---------- 监控 ----------
start_host_metrics_monitor() {
  local dir="$1"
  python3 "$MONITOR_DIR/ob_bench_monitor.py" \
    --out-dir "$dir" \
    --interval "$INTERVAL" \
    --ssh-user "$SSH_USER" \
    --ssh-port "$SSH_PORT" \
    --ob-nodes "$OB_NODES_CSV" \
    --odp-host "$ODP_HOST" \
    > "$dir/host_metrics_monitor.log" 2>&1 &
  MONITOR_PIDS+=("$!")
}

start_ob_sql_monitor() {
  local dir="$1"
  python3 "$MONITOR_DIR/ob_sql_monitor.py" \
    --out-dir "$dir" \
    --interval "$INTERVAL" \
    --host "$SYS_HOST" \
    --port "$SYS_PORT" \
    --user "$SYS_USER" \
    --password "$SYS_PASSWORD" \
    > "$dir/ob_sql_monitor.log" 2>&1 &
  MONITOR_PIDS+=("$!")
}

start_monitors() {
  local dir="$1"
  log "start monitors -> $dir"
  MONITOR_PIDS=()
  start_host_metrics_monitor "$dir"
  start_ob_sql_monitor "$dir"
}

stop_monitors() {
  if [ "${#MONITOR_PIDS[@]}" -gt 0 ]; then
    log "stop monitors"
    kill "${MONITOR_PIDS[@]}" >/dev/null 2>&1 || true
    wait "${MONITOR_PIDS[@]}" >/dev/null 2>&1 || true
    MONITOR_PIDS=()
  fi
}

# ---------- OB 生命周期 ----------
ob_start() {
  log "obd cluster start $CLUSTER"
  "$OBD" cluster start "$CLUSTER" >> "$SESSION_LOG" 2>&1
}

ob_stop() {
  log "obd cluster stop $CLUSTER"
  "$OBD" cluster stop "$CLUSTER" >> "$SESSION_LOG" 2>&1 || true
}

wait_ob_ready() {
  local deadline=$(( $(date +%s) + OB_READY_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if mysql "${mysql_sys_args[@]}" -N -B -e "SELECT 1" >/dev/null 2>&1; then
      log "OB is ready (sys connectable)"
      return 0
    fi
    sleep 5
  done
  log "OB not ready within ${OB_READY_TIMEOUT}s"
  return 1
}

create_database() {
  mysql "${mysql_perf_args[@]}" -e "CREATE DATABASE IF NOT EXISTS \`$MYSQL_DB\`;" >> "$SESSION_LOG" 2>&1
}

# ---------- uprobe agent / mongodb (仅 WITH_AGENT=1) ----------
agent_start() {
  [ "$WITH_AGENT" = "1" ] || return 0
  log "agent start (action=$AGENT_START_ACTION)"
  ( cd "$REPO_DIR" && "$PYTHON" uprobe/deploy/deploy_agent.py \
      -c "$AGENT_DEPLOY_YAML" --skip-build --action "$AGENT_START_ACTION" ) >> "$SESSION_LOG" 2>&1
}

agent_stop() {
  [ "$WITH_AGENT" = "1" ] || return 0
  log "agent stop"
  ( cd "$REPO_DIR" && "$PYTHON" uprobe/deploy/deploy_agent.py \
      -c "$AGENT_DEPLOY_YAML" --skip-build --action stop ) >> "$SESSION_LOG" 2>&1 || true
}

mongo_clear() {
  [ "$WITH_AGENT" = "1" ] || return 0
  log "clear mongodb: $MONGO_DROP_EVAL"
  docker exec "$MONGO_CONTAINER" mongosh "$MONGO_URI" --quiet --eval "$MONGO_DROP_EVAL" >> "$SESSION_LOG" 2>&1 || true
}

sb_cleanup() {
  local dir="$1"
  log "sysbench cleanup (清空数据)"
  sysbench "${sysbench_common[@]}" cleanup > "$dir/sysbench-cleanup.log" 2>&1 || true
}

# ---------- teardown: 清数据 -> 停 agent -> 停 OB -> 清 mongo ----------
teardown() {
  local dir="$1"
  sb_cleanup "$dir"
  agent_stop
  ob_stop
  mongo_clear
}

# ---------- 带 hung 检测运行 sysbench ----------
# 用法: run_sb_detect <phase> <logfile> <timeout> <sysbench-args...>
# 返回 0 成功; 1 判定为 hung/失败
run_sb_detect() {
  local phase="$1" logfile="$2" tmo="$3"; shift 3
  : > "$logfile"
  sysbench "$@" > "$logfile" 2>&1 &
  local sb_pid=$!
  local start hung rc
  start=$(date +%s)
  hung=0
  while kill -0 "$sb_pid" 2>/dev/null; do
    if grep -Eiq "$HUNG_PATTERN" "$logfile"; then
      hung=1
      log "[$phase] HUNG: matched pattern in $logfile -> kill sysbench pid=$sb_pid"
      kill -TERM "$sb_pid" 2>/dev/null || true
      sleep 3; kill -KILL "$sb_pid" 2>/dev/null || true
      break
    fi
    if [ $(( $(date +%s) - start )) -ge "$tmo" ]; then
      hung=1
      log "[$phase] HUNG: timeout ${tmo}s exceeded -> kill sysbench pid=$sb_pid"
      kill -TERM "$sb_pid" 2>/dev/null || true
      sleep 3; kill -KILL "$sb_pid" 2>/dev/null || true
      break
    fi
    sleep 3
  done
  wait "$sb_pid" 2>/dev/null; rc=$?
  if [ "$hung" -eq 1 ]; then
    return 1
  fi
  # 进程正常结束后再最终扫描一次 (捕获收尾打印的致命信息)
  if grep -Eiq "$HUNG_PATTERN" "$logfile"; then
    log "[$phase] HUNG: pattern found after exit"
    return 1
  fi
  if [ "$rc" -ne 0 ]; then
    log "[$phase] sysbench exit rc=$rc -> 判为失败"
    return 1
  fi
  return 0
}

# ---------- 结果校验 + 汇总 ----------
# 校验一次 run 是否为可用于取平均的有效结果; 有效则写入 SUMMARY 并返回0, 否则返回1(不计数)。
validate_and_record() {
  local n="$1" dir="$2" runlog="$3"
  local qps tps ttime
  qps=$(grep -E '^[[:space:]]*queries:' "$runlog" 2>/dev/null | grep -Eo '\([0-9.]+ per sec' | grep -Eo '[0-9.]+' | head -n1)
  tps=$(grep -E '^[[:space:]]*transactions:' "$runlog" 2>/dev/null | grep -Eo '\([0-9.]+ per sec' | grep -Eo '[0-9.]+' | head -n1)
  ttime=$(grep -E 'total time:' "$runlog" 2>/dev/null | grep -Eo '[0-9]+' | head -n1)
  if [ -z "$qps" ] || [ -z "$tps" ]; then
    log "结果无法解析 QPS/TPS (疑似不完整/截断) -> 判为无效, 不计数"
    return 1
  fi
  if [ -n "$ttime" ] && [ "$ttime" -lt "$((TIME * 9 / 10))" ]; then
    log "run 实际时长 ${ttime}s < 期望 ${TIME}s 的90% -> 判为无效, 不计数"
    return 1
  fi
  printf 'success #%d  dir=%s  qps=%s  tps=%s  time=%ss\n' "$n" "$dir" "$qps" "$tps" "${ttime:-NA}" | tee -a "$SUMMARY"
  return 0
}

# ---------- 主流程 ----------
cleanup_on_exit() {
  stop_monitors
}
trap cleanup_on_exit EXIT INT TERM

log "=== session start: session_dir=$SESSION_DIR ==="
log "config: cluster=$CLUSTER threads=$THREADS time=$TIME tables=$TABLES table_size=$TABLE_SIZE success_target=$SUCCESS_TARGET with_agent=$WITH_AGENT"
: > "$SUMMARY"

success=0
attempt=0

while [ "$success" -lt "$SUCCESS_TARGET" ] && [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
  attempt=$((attempt + 1))
  next=$((success + 1))
  dir="$SESSION_DIR/round${next}-try$(printf '%02d' "$attempt")"
  mkdir -p "$dir"
  log "----- attempt #$attempt (aiming success #$next) dir=$dir -----"

  # 1. 启动 OB
  if ! ob_start; then
    log "obd start 失败 -> stop 后重试"
    ob_stop
    mv "$dir" "${dir}-FAILED-start" 2>/dev/null || true
    continue
  fi
  if ! wait_ob_ready; then
    ob_stop
    mv "$dir" "${dir}-FAILED-start" 2>/dev/null || true
    continue
  fi

  # 2. (可选) 启动 uprobe/eBPF agent  —— 移到 prepare 之后, 只审计正式 run

  create_database

  # 3. 保证干净 + prepare
  sb_cleanup "$dir"
  log "sysbench prepare: tables=$TABLES table_size=$TABLE_SIZE threads=$PREPARE_THREADS"
  if ! run_sb_detect prepare "$dir/sysbench-prepare.log" "$PREPARE_TIMEOUT" \
        "${sysbench_common[@]}" --threads="$PREPARE_THREADS" prepare; then
    log "prepare 中断(疑似 clog hung) -> teardown, 重试"
    teardown "$dir"
    mv "$dir" "${dir}-FAILED-prepare" 2>/dev/null || true
    continue
  fi

  # 4. prepare 完成后: 清空 mongo(从空集合开始, 避免历史数据堆积影响 agent) + 启动 agent(只审计 run)
  mongo_clear
  agent_start

  # 5. run (带监控)
  log "sysbench run: threads=$THREADS time=$TIME rand_type=$RAND_TYPE"
  start_monitors "$dir"
  run_sb_detect run "$dir/sysbench-run-t${THREADS}.log" "$RUN_TIMEOUT" \
    "${sysbench_common[@]}" \
    --rand-type="$RAND_TYPE" \
    --threads="$THREADS" \
    --time="$TIME" \
    --report-interval="$INTERVAL" \
    --max-requests=0 \
    --percentile=99 \
    run
  run_rc=$?
  stop_monitors

  if [ "$run_rc" -ne 0 ]; then
    log "run 中断(疑似 clog hung) -> teardown, 重试"
    teardown "$dir"
    mv "$dir" "${dir}-FAILED-run" 2>/dev/null || true
    continue
  fi

  # 5. 校验结果有效性 -> 计数 (只有可用于取平均的完整结果才算成功)
  if ! validate_and_record "$next" "$dir" "$dir/sysbench-run-t${THREADS}.log"; then
    teardown "$dir"
    mv "$dir" "${dir}-FAILED-invalid" 2>/dev/null || true
    continue
  fi

  # 6. 成功: 清数据 -> 停 agent -> 停 OB -> 清 mongo, 计数
  teardown "$dir"
  success=$((success + 1))
  log "*** SUCCESS #$success at $dir ***"
done

log "=== session done: success=$success/$SUCCESS_TARGET attempts=$attempt ==="
echo "----- summary -----" | tee -a "$SESSION_LOG"
cat "$SUMMARY" | tee -a "$SESSION_LOG"

if [ "$success" -ge 1 ]; then
  avg_qps=$(grep -Eo 'qps=[0-9.]+' "$SUMMARY" | cut -d= -f2 | awk '{s+=$1;n++} END{if(n)printf "%.2f",s/n}')
  avg_tps=$(grep -Eo 'tps=[0-9.]+' "$SUMMARY" | cut -d= -f2 | awk '{s+=$1;n++} END{if(n)printf "%.2f",s/n}')
  printf 'AVERAGE over %d success runs: qps=%s tps=%s\n' "$success" "${avg_qps:-NA}" "${avg_tps:-NA}" | tee -a "$SUMMARY" "$SESSION_LOG"
fi

if [ "$success" -lt "$SUCCESS_TARGET" ]; then
  log "未达成 $SUCCESS_TARGET 次成功 (达到 MAX_ATTEMPTS=$MAX_ATTEMPTS), 请增大 MAX_ATTEMPTS 或排查集群 clog hung 根因后重跑"
  exit 1
fi
exit 0
