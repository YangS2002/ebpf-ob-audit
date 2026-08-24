# uprobe 点部署说明

单次打包产出一个自包含目录，内含 `agent/` 与 `collector/` 两个子目录（各带二进制、依赖库、配置、启动脚本）。逐机上传对应子目录即可运行，无需在目标机安装编译环境或 Python 依赖。

因 `server_ip` / `advertise_addr` 留空由程序自动探测本机 IPv4、id 自动派生，**一份配置可分发到所有同类节点**。

---

## 1. 编译环境要求（仅打包机需要）

在有编译环境的机器上打包一次，产物拷贝到线上机器运行。目标机不需要以下任何工具。

### 系统与工具链

| 组件 | 说明 |
|------|------|
| Linux x86_64 / aarch64 | 内核需支持 BPF CO-RE（建议 5.x+），agent 运行时需 root/CAP_BPF |
| `clang` + `llvm-strip` | 编译 BPF 目标代码、strip 调试信息 |
| `g++` | C++17，编译用户态 agent/collector |
| `make` | 构建入口 |
| `protoc` + `grpc_cpp_plugin` | 生成 gRPC/protobuf 桩代码（audit_upload、etcd rpc） |
| `pkg-config` | 探测下列库的编译/链接参数 |
| Python 3 | 运行打包脚本 `package.py`（仅标准库，无第三方依赖） |

### 依赖库（pkg-config 可发现）

- `grpc++`、`protobuf`
- `libmongoc-1.0`、`libbson-1.0`
- `libelf`、`zlib`（`-lelf -lz`）

### 仓库内置依赖（同级目录，随仓库获取）

- `../libbpf/`（静态编译为 `libbpf.a`）
- `../bpftool/`（生成 BPF skeleton）
- `../vmlinux/<arch>/vmlinux.h`（CO-RE 类型信息）

### 验证编译

```bash
cd uprobe
make            # 产出 bin/uprobe 与 bin/audit_collector
```

可选编译期开关：

```bash
# 覆盖内核 eBPF ringbuf 容量（默认 64MB），无需改配置文件
make CXXFLAGS="-O2 -Wall -std=c++17 -DAUDIT_RINGBUF_SIZE=$((128*1024*1024))"
```

---

## 2. 打包

```bash
python3 uprobe/deploy/package.py
```

默认产物：`uprobe/.deploy_bundle/audit-bundle/`

```text
audit-bundle/
  agent/
    bin/uprobe
    lib/*.so
    conf/agent.yaml
    start_agent.sh
    logs/  run/
  collector/
    bin/audit_collector
    lib/*.so
    audit_schema.json
    conf/collector.yaml
    start_collector.sh
    logs/  run/
```

常用参数：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--build-dir` | `uprobe/.deploy_bundle` | 产物输出目录 |
| `--name` | `audit-bundle` | 产物文件夹名 |
| `--agent-config` | `deploy/agent.yaml` | 打入 agent 的运行配置 |
| `--collector-config` | `deploy/collector.yaml` | 打入 collector 的运行配置 |
| `--skip-build` | 关 | 复用已有二进制，跳过 `make` |

> 打包**不生成**配置文件，直接拷贝 `deploy/agent.yaml` 与 `deploy/collector.yaml`。改配置只需改这两个文件后重新打包。

---

## 3. 部署配置

打包前按环境确认下列少数值，其余留默认。

### agent（`deploy/agent.yaml`）

| 键 | 必填 | 说明 |
|----|------|------|
| `collector.discovery.etcd_endpoints` | 是 | etcd 地址，如 `http://<ip>:2379` |
| `uprobe.observer_path` | 是 | observer 可执行文件路径，各机一致时用默认值 |
| `uprobe.offset` | 是 | `record_request` 入口偏移，同版本 observer 相同 |
| `agent.server_ip` | 否 | 留空自动探测本机出网 IPv4 |
| `agent.id` | 否 | 留空自动派生 `agent-<server_ip>` |

### collector（`deploy/collector.yaml`）

| 键 | 必填 | 说明 |
|----|------|------|
| `collector.registry.etcd_endpoints` | 是 | etcd 地址 |
| `mongodb.uri` | 是 | MongoDB 连接串（含凭据，无默认值） |
| `storage.type` | 是 | 写 MongoDB 须显式设 `mongodb`（默认 `local` 仅落本地文件） |
| `collector.listen_addr` | 否 | 默认 `0.0.0.0:50051` |
| `collector.registry.advertise_addr` | 否 | 留空自动探测 `<本机IPv4>:<listen_port>` |
| `collector.registry.collector_id` | 否 | 留空自动派生 `collector-<advertise_addr>` |

---

## 4. 上线（点部署）

将 `audit-bundle/collector/` 上传到 collector 机、`audit-bundle/agent/` 上传到各 agent 机。

collector 机：

```bash
./start_collector.sh
# 日志：logs/collector.log
```

agent 机（BPF 需要 root/CAP_BPF）：

```bash
sudo ./start_agent.sh
# 日志：logs/agent.log
```

启动顺序：先起 collector（注册到 etcd），agent 通过 etcd 服务发现自动连上。
