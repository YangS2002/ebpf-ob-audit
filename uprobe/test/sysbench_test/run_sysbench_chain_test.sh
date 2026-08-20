#!/usr/bin/env bash
# 链路一般性测试用 sysbench 驱动脚本（非压测基准，用于验证采集链路优化是否正向）。
# 使用标准 oltp_read_write 脚本，多表分散到 3 台 OB，定时并发运行。
#
# 用法:
#   ./run_sysbench_chain_test.sh cleanup   # 删除 sbtest* 表
#   ./run_sysbench_chain_test.sh prepare   # 建表并灌数
#   ./run_sysbench_chain_test.sh run       # 正式测试(默认 120s / 8 并发)
#   ./run_sysbench_chain_test.sh all       # cleanup -> prepare -> run
#
# 可用环境变量覆盖默认值，例如:
#   THREADS=4 RUN_TIME=60 ./run_sysbench_chain_test.sh run

set -euo pipefail

LUA="${LUA:-/usr/share/sysbench/oltp_read_write.lua}"

# prepare/cleanup 的单host入口(DDL/灌数任一 observer 都行)。
MYSQL_HOST="${MYSQL_HOST:-7.27.43.136}"
MYSQL_PORT="${MYSQL_PORT:-2881}"
MYSQL_USER="${MYSQL_USER:-root@ebpf_tenant}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
MYSQL_DB="${MYSQL_DB:-test}"

# run 阶段把连接分散到 3 台 observer, 让三台都产审计记录。
# 审计记录在"客户端连接落地的 observer"上生成(SQL 入口/会话所在 server),
# 不是 tablet leader 所在 server, 所以必须分散连接入口, 单host会全打到一台。
# sysbench mysql driver 的 --mysql-host 支持逗号列表, 各线程连接按 host 轮转。
HOSTS="${HOSTS:-7.27.43.136,7.27.43.137,7.27.43.138}"

# tables 用多表把 tablet 均衡到 3 个 unit(3 台 OB 都产审计); table-size 每表行数。
TABLES="${TABLES:-9}"
TABLE_SIZE="${TABLE_SIZE:-10000}"

# 并发封顶 8(145 与 mongodb 同机，需留资源); 定时 120s; 每 10s 打点。
THREADS="${THREADS:-8}"
RUN_TIME="${RUN_TIME:-120}"
REPORT_INTERVAL="${REPORT_INTERVAL:-10}"

CONN=(
  --db-driver=mysql
  --mysql-port="$MYSQL_PORT"
  --mysql-user="$MYSQL_USER"
  --mysql-password="$MYSQL_PASSWORD"
  --mysql-db="$MYSQL_DB"
  --tables="$TABLES"
  --table-size="$TABLE_SIZE"
  # 禁用服务端预处理: 规避 OB 单会话游标上限(err 5930 maximum open cursors exceeded),
  # 且每条走完整 SQL 文本,审计记录更贴近真实。
  --db-ps-mode=disable
)

usage() {
  echo "usage: $0 {cleanup|prepare|run|all}" >&2
  exit 1
}

do_cleanup() {
  echo "[cleanup] dropping $TABLES tables in $MYSQL_DB@$MYSQL_HOST"
  sysbench "$LUA" "${CONN[@]}" --mysql-host="$MYSQL_HOST" --threads=1 cleanup
}

do_prepare() {
  echo "[prepare] creating $TABLES tables x $TABLE_SIZE rows"
  sysbench "$LUA" "${CONN[@]}" --mysql-host="$MYSQL_HOST" --threads="$THREADS" prepare
}

do_run() {
  # --mysql-host 传逗号列表, sysbench 把各线程连接轮转到这些 host。
  echo "[run] hosts=$HOSTS threads=$THREADS time=${RUN_TIME}s report_interval=${REPORT_INTERVAL}s"
  sysbench "$LUA" "${CONN[@]}" --mysql-host="$HOSTS" \
    --threads="$THREADS" --time="$RUN_TIME" --report-interval="$REPORT_INTERVAL" run
}

case "${1:-}" in
  cleanup) do_cleanup ;;
  prepare) do_prepare ;;
  run)     do_run ;;
  all)     do_cleanup; do_prepare; do_run ;;
  *)       usage ;;
esac
