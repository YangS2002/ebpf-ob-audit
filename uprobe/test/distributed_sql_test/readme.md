# 分布式 OB SQL 记录测试

## 目标

验证当前采集方式在分布式 OB 下是否能得到用户级 SQL：

```text
每台 OBServer 本地 uprobe 全量采集
过滤 is_inner_sql
本地合并 fragment
上送/落盘后统一分析
```

重点不是只验证 SQL 能被捕获，而是验证：

```text
同一用户 SQL 在几个节点出现
入口节点和远端节点 query_sql 是否一致
trace_id 是否跨节点一致
request_id 是否只具备本地意义
is_inner_sql=false 是否足够过滤出用户级 SQL
```

## 文件

```text
workload.sql                 正常分布式 workload
expected.sql                 check_audit_sql 期望 SQL
error_workload.sql           分布式错误 workload
error_expected.sql           错误 SQL 期望
run_one.py                   单个测试：deploy/start/stop + 官方 OB_SQL_AUDIT 与 collector 记录比对
run_all.py                   批量测试：依次执行正常与错误 workload
```

## 建议执行方式

1. 所有 OBServer 同时启动采集。
2. 客户端分别连接不同入口节点执行 `workload.sql`。
3. 每个节点各保存一份 `.adt`。
4. 分别转 CSV，再汇总分析。
5. 使用 `check_audit_sql` 只做“本节点是否捕获到期望 SQL”的基础校验。

示例：

```bash
./uprobe/bin/check_audit_sql node_a.adt uprobe/test/distributed_sql_test/expected.sql --print-matched
./uprobe/bin/check_audit_sql node_b.adt uprobe/test/distributed_sql_test/expected.sql --print-matched
./uprobe/bin/check_audit_sql node_c.adt uprobe/test/distributed_sql_test/expected.sql --print-matched
```

## 多机自动比对测试

自动流程：

```text
1. 读取 deploy 配置。
2. 本机构建并 deploy uprobe 到所有目标 OBServer。
3. start 所有远端 uprobe。
4. 执行 workload SQL。
5. 无论 SQL 是否成功，都会 stop 远端 uprobe，触发批处理完整发送到 collector。
6. 从 GV$OB_SQL_AUDIT 导出官方记录，密码默认 root@sys/oceanbase。
7. 从 collector 服务器下载 `.adt`。
8. 转 CSV，按 workload SQL 在 collector 中定位记录，再用 `query_sql + trace_id` 到 GV$OB_SQL_AUDIT 中定位官方记录并比对字段。
```

前提：collector 已启动并写入 `collector_events.adt`，deploy yaml 中 `agent.global.collector_addr` 指向 collector。

```bash
./uprobe/bin/audit_collector 0.0.0.0:50051 collector_events.adt
```

### 单独比较已有记录

已有官方 TSV 和 collector CSV 时，直接比较：

```bash
python3 uprobe/test/distributed_sql_test/compare_official_collector.py \
  --workload uprobe/test/distributed_sql_test/workload.sql \
  --official-tsv uprobe/test/distributed_sql_test/out/single/official_ob_sql_audit.tsv \
  --collector-csv uprobe/test/distributed_sql_test/out/single/collector_events.csv \
  --out-dir uprobe/test/distributed_sql_test/out/single/compare
```

已有 collector ADT 时，脚本会先转 CSV 再比较：

```bash
python3 uprobe/test/distributed_sql_test/compare_official_collector.py \
  --workload uprobe/test/distributed_sql_test/workload.sql \
  --official-tsv uprobe/test/distributed_sql_test/out/single/official_ob_sql_audit.tsv \
  --collector-adt uprobe/test/distributed_sql_test/out/single/collector_events.adt \
  --out-dir uprobe/test/distributed_sql_test/out/single/compare
```

比较逻辑：

```text
1. 从 workload 加载 SQL，删除注释并归一化空白。
2. 每条 workload SQL 先在 collector 中按 query_sql 搜索。
3. collector 缺失则报告 collector_missing。
4. collector 命中多条则报警 duplicate collector，暂不比较该 SQL。
5. collector 命中 1 条后，取该条 trace_id。
6. 在官方 GV$OB_SQL_AUDIT 中按 query_sql + trace_id 定位唯一行。
7. 官方缺失/多条分别报告 official_missing / duplicate official。
8. 唯一命中后按字段映射比较，PASS 行绿色输出随机字段，失败行输出所有不一致字段。
```

### 单个测试

```bash
python3 uprobe/test/distributed_sql_test/run_one.py \
  --deploy-config uprobe/deploy/agent-deploy.example.yaml \
  --workload uprobe/test/distributed_sql_test/workload.sql \
  --ob-host 7.27.43.145 \
  --collector-path /home/yangshuo17/ebpf-ob-audit/collector_events.adt \
  --out-dir uprobe/test/distributed_sql_test/out/single
```

错误 workload：

```bash
python3 uprobe/test/distributed_sql_test/run_one.py \
  --deploy-config uprobe/deploy/agent-deploy.example.yaml \
  --workload uprobe/test/distributed_sql_test/error_workload.sql \
  --mysql-force \
  --ob-host 7.27.43.145 \
  --collector-path /home/yangshuo17/ebpf-ob-audit/collector_events.adt \
  --out-dir uprobe/test/distributed_sql_test/out/error
```

### 批量测试

```bash
python3 uprobe/test/distributed_sql_test/run_all.py \
  --deploy-config uprobe/deploy/agent-deploy.example.yaml \
  --ob-host 7.27.43.145 \
  --collector-path /home/yangshuo17/ebpf-ob-audit/collector_events.adt \
  --out-dir uprobe/test/distributed_sql_test/out/batch
```

`run_all.py` 默认第一轮 deploy，后续 case 复用部署目录，只重新 start/stop。若每个 case 都重新 deploy，加 `--deploy-each-case`。

常用参数：

```text
--workload                         默认 workload.sql
--workload-user                    默认 root@sys
--workload-password                默认 oceanbase
--audit-user                       默认 root@sys
--audit-password                   默认 oceanbase
--skip-build                       deploy 时跳过 make -C uprobe
--skip-deploy                      已部署时跳过 deploy，只 start/stop
--collector-host/user/ssh-port     覆盖 deploy yaml 中的 collector SSH 信息
--collector-password               覆盖 deploy yaml 中 SSH 密码；空值表示免密
--collector-stop-wait-seconds      stop 后等待 collector 落盘，默认 2 秒
```

输出：

```text
out/<case>/official_ob_sql_audit.tsv       官方 GV$OB_SQL_AUDIT 原始导出
out/<case>/collector_events.adt            从 collector 下载的批处理记录
out/<case>/collector_events.csv            collector 转换 CSV
out/<case>/compare/official.normalized.csv 官方归一化记录
out/<case>/compare/collector.normalized.csv collector 归一化记录
out/<case>/compare/compare_report.txt      SQL 级比对结果
```


### 分区与查询

```text
hash 分区点查
range 分区范围查
IN 多分区查
全表扫描
GROUP BY 聚合
ORDER BY + LIMIT
DISTINCT
UNION ALL
EXISTS 子查询
IN 子查询
两表 join
三表 join
```

### 写入与事务

```text
单分区 UPDATE
多分区 UPDATE
单分区 DELETE
多分区 DELETE
INSERT SELECT
UPSERT
REPLACE
多分区事务 COMMIT
多分区事务 ROLLBACK
```

### PS 协议

```text
PS 点查
PS 范围查
PS UPDATE
PS JOIN
```

检查点：`EXECUTE` 对应记录应保留 prepared 原 SQL，例如：

```sql
SELECT customer_id, name FROM ebpf_audit_dist_test.dist_customer WHERE customer_id = ?
```

不是只记录：

```sql
EXECUTE ps_dist_point_select USING @dist_customer_id
```

### 错误场景

```text
主键冲突
唯一键冲突
列不存在
表不存在
类型转换/表达式错误候选
无匹配 DELETE
```

## 分布式重点检查

CSV 汇总后按这些字段观察：

```text
observer_id / 节点 IP
trace_id
sql_id
request_id
session_id
proxy_session_id
query_sql
ret_code
affected_rows
return_rows
elapsed_time
execute_time
```

预期：

```text
request_id 不跨节点一致
trace_id 可能跨节点一致，需要实测
同一 query_sql 可能多节点出现
远端节点可能无记录，也可能出现非 inner 记录
```

如果同一用户 SQL 在多个节点都出现 `is_inner_sql=false`，说明：

```text
is_inner_sql 只能初筛，不能完整过滤用户级 SQL
collector 必须按 trace_id/query_sql_hash/session/time_window 做逻辑聚合
```
