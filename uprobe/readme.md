# 1. 构建libbpf开发环境

1. clone官方模板

[eunomia-bpf/libbpf-starter-template: Template designed to get new developers with libbpf development.](https://github.com/eunomia-bpf/libbpf-starter-template)

2. 构建开发容器

```
git submodule update --init --recursive
docker build -f dev.dockerfile -t ebpf-ob-audit-dev .
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
# 构建uprobe探针
make -C uprobe
./uprobe/uprobe target_proc_path target_func_offset
pidof observer # 查找进程id
readlink -f /proc/972084/exe # 读取可执行文件位置
# 查找目标函数的偏移
readelf -Ws /home/yangshuo17/obd_obtest/observer1/bin/observer | c++filt | grep 'ObMySQLRequestManager::record_request'
# 例如
./uprobe/bin/uprobe /home/yangshuo17/obd_obtest/observer1/bin/observer 0x000000000a7bae60
./uprobe/bin/uprobe /home/yangshuo17/observer/bin/observer  0x000000000bf18950
```

4. 构建运行环境

```
docker build -f dockerfile -t ebpf-ob-audit .
docker run --rm -it --privileged \
  --pid=host \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug \
  ebpf-ob-audit
```

# 2. 导出GV$OB_SQL_AUDIT
mysql -h7.27.43.145 -P2881 -uroot@sys -A --batch --raw -e "SELECT * from oceanbase.GV\$OB_SQL_AUDIT where tenant_name='ebpf_audit_tenant_a'" -p >audit.tsv 
