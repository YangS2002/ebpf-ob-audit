# uprobe deploy commands

## Agent

配置文件：

```bash
uprobe/deploy/agent-deploy.example.yaml
```

部署并启动：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action deploy-start
```

只部署：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action deploy
```

启动：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action start
```

停止：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action stop
```

重启：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action restart
```

状态：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action status
```

清理部署目录：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action clean
```

跳过本地构建：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action deploy-start \
  --skip-build
```

只打印命令，不执行远端修改：

```bash
python3 uprobe/deploy/deploy_agent.py \
  -c uprobe/deploy/agent-deploy.example.yaml \
  --action deploy-start \
  --dry-run
```

## Collector

配置文件：

```bash
uprobe/deploy/collector-deploy.example.yaml
```

部署并启动：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action deploy-start
```

只部署：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action deploy
```

启动：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action start
```

停止：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action stop
```

重启：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action restart
```

查看最后 50 行 collector 日志：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action logs
```

清空 collector 日志：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action clear-logs
```

清理部署目录：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action clean
```

跳过本地构建：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action deploy-start \
  --skip-build
```

只打印命令，不执行远端修改：

```bash
python3 uprobe/deploy/deploy_collector.py \
  -c uprobe/deploy/collector-deploy.example.yaml \
  --action deploy-start \
  --dry-run
```

## Collector 远端目录结构

同一机器一份 collector 可执行文件，多份配置：

```text
${deploy_home}/
  bin/audit_collector
  lib/*.so
  conf/collector-50051.conf
  conf/collector-50052.conf
  conf/collector-50053.conf
  run/start_collector.sh
  run/collector-50051.pid
  run/collector-50052.pid
  run/collector-50053.pid
  logs/collector.log
```

collector 日志统一写入：

```text
logs/collector.log
```

每行带 collector 前缀：

```text
[collector-50051 port=50051] ...
```
