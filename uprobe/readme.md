# uprobe 使用说明

本文记录当前 uprobe/collector/MongoDB 全链路测试流程。所有命令均使用当前机器真实路径，可直接复制执行。

## 1. 构建

```bash
git -C /home/yangshuo17/ebpf-ob-audit submodule update --init --recursive
make -C uprobe
```

会生成：

```text
uprobe/bin/uprobe
uprobe/bin/audit_collector
uprobe/bin/adt_to_csv
```

开发容器可选：

```bash
docker build -f dev.dockerfile -t ebpf-ob-audit-dev /home/yangshuo17/ebpf-ob-audit
docker run -it --privileged --pid=host \
  -v /home/yangshuo17/ebpf-ob-audit:/root/ebpf-ob-audit \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /home/yangshuo17:/home/yangshuo17 \
  ebpf-ob-audit-dev
```

## 2. 当前链路

```text
observer record_request
  -> eBPF uprobe agent
  -> gRPC AuditBatch
  -> audit_collector
  -> MongoDB ob_audit.audit_events
  -> uprobe/tools/mongo_to_csv.py
  -> uprobe/test/distributed_sql_test/compare_official_collector.py
  -> GV$OB_SQL_AUDIT 对比
```

collector 支持 MongoDB 存储。agent 支持 collector 服务发现，默认通过 etcd 服务名 `audit-collector` 选择 collector。

## 3. 启动 etcd

collector 注册和 agent 服务发现依赖 etcd。单节点测试可这样启动：

```bash
etcd \
  --name node1 \
  --data-dir /home/yangshuo17/etcd-data \
  --listen-client-urls http://0.0.0.0:2379 \
  --advertise-client-urls http://7.27.43.139:2379 \
  --listen-peer-urls http://0.0.0.0:2381 \
  --initial-advertise-peer-urls http://7.27.43.139:2381 \
  --initial-cluster node1=http://7.27.43.139:2381 \
  --initial-cluster-state new
```

如果复用已有 `/home/yangshuo17/etcd-data`，`--initial-cluster-state new` 可能因旧数据报错。测试环境可先停止 etcd，再清理旧数据目录后启动：

```bash
sudo systemctl stop etcd
rm -rf /home/yangshuo17/etcd-data
```

注意：etcd 只负责服务注册/发现，不是数据通道。停 etcd 不会切断已有 `agent -> collector -> MongoDB` 数据链路。

## 4. 部署 collector

当前配置文件：

```text
uprobe/deploy/collector-deploy.example.yaml
```

关键配置：

```yaml
collector:
  global:
    storage: mongodb
    registry_enabled: true
    registry_etcd_endpoints: http://7.27.43.139:2379
    registry_service_name: audit-collector
    mongodb_uri: mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit
    mongodb_database: ob_audit
    mongodb_collection: audit_events
```

部署并启动：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action deploy-start
```

常用操作：

```bash
python3 uprobe/deploy/deploy_collector.py -c uprobe/deploy/collector-deploy.example.yaml --action logs
python3 uprobe/deploy/deploy_collector.py -c uprobe/deploy/collector-deploy.example.yaml --action restart
python3 uprobe/deploy/deploy_collector.py -c uprobe/deploy/collector-deploy.example.yaml --action stop
python3 uprobe/deploy/deploy_collector.py -c uprobe/deploy/collector-deploy.example.yaml --action clear-logs
python3 uprobe/deploy/deploy_collector.py -c uprobe/deploy/collector-deploy.example.yaml --action clean
```

## 5. 部署 agent

当前配置文件：

```text
uprobe/deploy/agent-deploy.example.yaml
```

关键配置：

```yaml
agent:
  global:
    deploy_home: /home/yangshuo17/ebpf-ob-audit-agent
    collector_addr: 7.27.43.138:50051
    collector_discovery_enabled: true
    collector_discovery_etcd_endpoints: http://7.27.43.139:2379
    collector_discovery_service_name: audit-collector
    collector_discovery_watch: true
    collector_discovery_selection_policy: hash_agent
    grpc_batch_bytes: 262144
    grpc_flush_interval_ms: 1000
    grpc_timeout_ms: 2000
    observer_path: /home/yangshuo17/ob3node/bin/observer
    offset: "0x000000000bf18950"
```

`grpc_flush_interval_ms` 会让未满 `grpc_batch_bytes` 的小批量测试 SQL 定时上送，避免 collector/MongoDB 暂时无数据。

部署并启动：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action deploy-start
```

常用操作：

```bash
python3 uprobe/deploy/deploy_agent.py -c uprobe/deploy/agent-deploy.example.yaml --action status
python3 uprobe/deploy/deploy_agent.py -c uprobe/deploy/agent-deploy.example.yaml --action restart
python3 uprobe/deploy/deploy_agent.py -c uprobe/deploy/agent-deploy.example.yaml --action stop
python3 uprobe/deploy/deploy_agent.py -c uprobe/deploy/agent-deploy.example.yaml --action clean
python3 uprobe/deploy/deploy_agent.py -c uprobe/deploy/agent-deploy.example.yaml --dry-run
```

部署包在目标机：

```text
/home/yangshuo17/ebpf-ob-audit-agent/bin/uprobe
/home/yangshuo17/ebpf-ob-audit-agent/conf/uprobe.conf
/home/yangshuo17/ebpf-ob-audit-agent/lib/*.so*
/home/yangshuo17/ebpf-ob-audit-agent/run/start_agent.sh
```

目标机不需要安装 gRPC/protobuf 构建依赖，但需要 eBPF 权限、正确 observer 路径和函数 offset。

## 6. 手工运行 agent/collector

本地文件存储 collector：

```bash
uprobe/bin/audit_collector \
  0.0.0.0:50051 \
  uprobe/test/full_connectivity_test/out/manual/collector_events.adt
```

agent：

```bash
uprobe/bin/uprobe \
  /home/yangshuo17/ob3node/bin/observer \
  0x000000000bf18950 \
  uprobe/test/full_connectivity_test/out/manual/out.adt \
  uprobe/uprobe.conf
```

查 observer 和 offset：

```bash
pidof observer
readlink -f /proc/$(pidof observer | cut -d ' ' -f 1)/exe
readelf -Ws /home/yangshuo17/ob3node/bin/observer | c++filt | grep 'ObMySQLRequestManager::record_request'
```

## 7. 全联通测试

测试目录：

```text
uprobe/test/full_connectivity_test/
uprobe/test/full_connectivity_test/workload.sql
uprobe/test/full_connectivity_test/run_one_mongo.py
uprobe/test/full_connectivity_test/run_all_mongo.py
uprobe/test/full_connectivity_test/readme.md
```

`uprobe/test/full_connectivity_test/workload.sql` 会先：

```sql
CREATE DATABASE IF NOT EXISTS ebpf_audit_dist_test;
USE ebpf_audit_dist_test;
```

后续 SQL 使用未带库名前缀的表名，保证审计记录带 `db_name=ebpf_audit_dist_test`，方便 MongoDB 过滤。

### 单次运行

```bash
python3 uprobe/test/full_connectivity_test/run_one_mongo.py \
  --out-dir uprobe/test/full_connectivity_test/out/single_mongo \
  --mongo-query '{"db_name":"ebpf_audit_dist_test"}'
```

默认参数：

```text
--ob-host 7.27.43.136
--ob-port 2881
--workload-user root@sys
--workload-password oceanbase
--audit-user root@sys
--audit-password oceanbase
--mongo-uri mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit
--mongo-db ob_audit
--mongo-collection audit_events
--mongo-export-wait-seconds 5
```

输出：

```text
uprobe/test/full_connectivity_test/out/single_mongo/official_ob_sql_audit.tsv
uprobe/test/full_connectivity_test/out/single_mongo/collector_events.csv
uprobe/test/full_connectivity_test/out/single_mongo/compare/
```

`run_one_mongo.py` 默认会清空 MongoDB collection。复用已有 collection 时加：

```bash
python3 uprobe/test/full_connectivity_test/run_one_mongo.py \
  --out-dir uprobe/test/full_connectivity_test/out/single_mongo \
  --mongo-query '{"db_name":"ebpf_audit_dist_test"}' \
  --no-clear-mongo
```

`--deploy-config` 目前无实际作用，仅保留兼容旧命令。

### 批量运行

```bash
python3 uprobe/test/full_connectivity_test/run_all_mongo.py \
  --out-dir uprobe/test/full_connectivity_test/out/batch_mongo \
  --mongo-query '{"db_name":"ebpf_audit_dist_test"}'
```

当前批量只有一个 case：`full_connectivity`。

## 8. 只导出 MongoDB

```bash
python3 uprobe/tools/mongo_to_csv.py \
  --uri 'mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit' \
  --db ob_audit \
  --collection audit_events \
  --query '{"db_name":"ebpf_audit_dist_test"}' \
  --output uprobe/test/full_connectivity_test/out/manual/collector_events.csv
```

导出时会：

- 将 `plan_type` 导出为官方原值字段 `plan_type_value`。
- 将 `plan_type_name` 导出为名称。
- 过滤 SQL 中不可见控制字符，避免 CSV/normalize 结果异常。

## 9. 手工导出官方审计表

```bash
mysql -h7.27.43.136 -P2881 -uroot@sys -A --batch --raw \
  -e "SELECT * FROM oceanbase.GV\$OB_SQL_AUDIT WHERE is_inner_sql=0" \
  -p > uprobe/test/full_connectivity_test/out/manual/official_ob_sql_audit.tsv
```

全联通脚本会自动执行官方导出并和 MongoDB collector 数据对比，通常不需要手工导出。
