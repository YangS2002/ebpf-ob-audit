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
distributed_sql_workload.sql          正常分布式 workload
expected_distributed_sql.sql          check_audit_sql 期望 SQL
distributed_error_workload.sql        分布式错误 workload
expected_distributed_error_sql.sql    错误 SQL 期望
```

## 建议执行方式

1. 所有 OBServer 同时启动采集。
2. 客户端分别连接不同入口节点执行 `distributed_sql_workload.sql`。
3. 每个节点各保存一份 `.adt`。
4. 分别转 CSV，再汇总分析。
5. 使用 `check_audit_sql` 只做“本节点是否捕获到期望 SQL”的基础校验。

示例：

```bash
./uprobe/bin/check_audit_sql node_a.adt uprobe/test/distributed_sql_test/expected_distributed_sql.sql --print-matched
./uprobe/bin/check_audit_sql node_b.adt uprobe/test/distributed_sql_test/expected_distributed_sql.sql --print-matched
./uprobe/bin/check_audit_sql node_c.adt uprobe/test/distributed_sql_test/expected_distributed_sql.sql --print-matched
```

## 覆盖场景

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
