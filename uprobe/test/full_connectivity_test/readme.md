# 全联通测试

本目录用于验证整条链路是否联通：OB workload 执行、agent uprobe 采集、gRPC 上送 collector、MongoDB 落库、导出 CSV、与 `GV$OB_SQL_AUDIT` 对比。

## 文件

- `workload.sql`：全联通 SQL workload。先 `CREATE DATABASE`，再 `USE ebpf_audit_dist_test`，后续 SQL 不再使用 `db.table` 形式，确保审计记录里带 `db_name`，便于 MongoDB 过滤。
- `run_one_mongo.py`：执行单个 workload，导出 official 和 MongoDB collector 数据，并运行对比。
- `run_all_mongo.py`：批量执行本目录全部全联通用例，目前只有 `full_connectivity`。

## 前置条件

1. collector 已启动，且配置 `storage=mongodb`。
2. 所有 OBServer 上 agent 已部署并启动。
3. MongoDB 可从本机访问。
4. 本机可连接 OceanBase MySQL 端口。
5. Python 环境有 `pymongo`。

## 运行单用例

```bash
python3 uprobe/test/full_connectivity_test/run_one_mongo.py \
  --out-dir uprobe/test/full_connectivity_test/out/single_mongo
```

常用参数：

```bash
--ob-host 7.27.43.136
--ob-port 2881
--workload-user root@sys
--workload-password oceanbase
--audit-user root@sys
--audit-password oceanbase
--mongo-uri 'mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit'
--mongo-query '{"db_name":"ebpf_audit_dist_test"}'
--mongo-export-wait-seconds 5
```

输出：

```text
out/single_mongo/
  official_ob_sql_audit.tsv
  collector_events.csv
  compare/
```

## 运行批量用例

```bash
python3 uprobe/test/full_connectivity_test/run_all_mongo.py \
  --out-dir uprobe/test/full_connectivity_test/out/batch_mongo
```

## MongoDB 按库过滤

workload 已使用 `USE ebpf_audit_dist_test`，因此 collector 写入 MongoDB 的记录应包含：

```json
{"db_name":"ebpf_audit_dist_test"}
```

可通过参数只导出本测试数据：

```bash
--mongo-query '{"db_name":"ebpf_audit_dist_test"}'
```

## 注意

`run_one_mongo.py` 默认会清空 MongoDB collection。若要复用 collection 中已有数据，加：

```bash
--no-clear-mongo
```
