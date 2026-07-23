# 1. 构建libbpf开发环境

1. clone官方模板

[eunomia-bpf/libbpf-starter-template: Template designed to get new developers with libbpf development.](https://github.com/eunomia-bpf/libbpf-starter-template)

2. 构建开发容器

```
git submodule update --init --recursive
docker build -f dev.dockerfile -t ebpf-ob-audit-dev .
# gRPC 构建依赖已包含：protobuf-compiler protobuf-compiler-grpc libprotobuf-dev libgrpc++-dev。
# 进入容器后可执行：make -C uprobe grpc
# OB4.2.5.5 源码编译版
docker run -it --privileged   --pid=host  \
 -v "$PWD":/root \
  -v /sys/kernel/tracing:/sys/kernel/tracing  \
   -v /sys/kernel/debug:/sys/kernel/debug \
     -v /home/yangshuo17/:/home/yangshuo17   ebpf-ob-audit-dev

    -v /home/yangshuo17/oceanbase 挂载到oceanbase

# OBD 部署版
docker run -it --privileged   --pid=host  \
 -v "$PWD":/root \
  -v /sys/kernel/tracing:/sys/kernel/tracing  \
   -v /sys/kernel/debug:/sys/kernel/debug \
     -v /home/yangshuo17/:/home/yangshuo17   ebpf-ob-audit-dev
```

3. 构建开发环境

```
# 构建官方demo
make build
./src/bootstra

# 构建uprobe探针和消费者程序
make -C uprobe

./uprobe/bin/audit_collector 0.0.0.0:50051 collector_events.adt

# 配置 uprobe/uprobe.conf: collector_addr=127.0.0.1:50051
./uprobe/bin/uprobe /home/yangshuo17/observer/bin/observer 0x000000000bf18950 out.adt /home/yangshuo17/ebpf-ob-audit/uprobe/uprobe.conf

./uprobe/uprobe target_proc_path target_func_offset
pidof observer # 查找进程id

readlink -f /proc/972084/exe # 读取可执行文件位置

# 查找目标函数的偏移
readelf -Ws /home/yangshuo17/obd_obtest/observer1/bin/observer | c++filt | grep 'ObMySQLRequestManager::record_request'

# 例如
./uprobe/bin/uprobe /home/yangshuo17/obd_obtest/observer1/bin/observer 0x000000000a7bae60
./uprobe/bin/uprobe /home/yangshuo17/observer/bin/observer  0x000000000bf18950 out.adt /home/yangshuo17/ebpf-ob-audit/uprobe/uprobe.conf
```

4. 多机部署 agent

```
# 可选：完整 YAML 支持。deploy_agent.py 内置 mini-3node.yaml 子集解析，不安装也能解析基础 OBD 配置。
pip3 install -r uprobe/deploy/requirements.txt

# 参考配置
cp uprobe/deploy/agent-deploy.example.yaml agent-deploy.yaml

# 本机编译、打包并通过 SSH 部署到所有 oceanbase-ce.servers 节点
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action deploy

# 部署后立即后台启动，并返回每台机器的运行状态和最近日志
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action deploy-start

# 检查每台目标机是否部署、uprobe 是否运行、collector TCP 是否连通，并显示最近日志
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action status

# 启动/停止/重启所有目标机 agent
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action start
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action stop
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action restart

# 停止 agent 并删除目标机部署目录
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --action clean

# 不修改远端，只打印 SSH/SCP/管理命令
python3 uprobe/deploy/deploy_agent.py -c agent-deploy.yaml --dry-run
```

部署包包含：

```
bin/uprobe
conf/uprobe.conf
lib/*.so*
run/start_agent.sh
```

目标机器不需要安装 gRPC/protobuf 构建依赖。运行时仍要求目标机器具备 eBPF 权限、observer 路径和函数 offset 正确。

5. 构建运行环境

```
docker build -f dockerfile -t ebpf-ob-audit .
docker run --rm -it --privileged \
  --pid=host \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug \
  ebpf-ob-audit
```

# 2. 导出GV$OB_SQL_AUDIT
mysql -h7.27.43.137 -P2881 -uroot@sys -A --batch --raw -e "SELECT * from oceanbase.GV\$OB_SQL_AUDIT where is_inner_sql=0 " -p >audit.tsv 
