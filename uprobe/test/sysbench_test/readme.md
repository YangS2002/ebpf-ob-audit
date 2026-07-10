# sysbench 生成sql并uprobe记录测试
events = sql数，每个events产生一个sql
# 清理目标表的数据
sysbench uprobe/test/sysbench_print_sql.lua \
  --mysql-host=7.27.43.145 \
  --mysql-port=2881 \
  --mysql-user=root@ebpf_tenant \
  --mysql-password='' \
  --mysql-db=test \
  --threads=1 \
  --events=1 \
  --table-name=sbtest1 \
  --sql-output=uprobe/test/sysbench_generated.sql \
  cleanup

# 准备数据
sysbench uprobe/test/sysbench_print_sql.lua \
  --mysql-host=7.27.43.145 \
  --mysql-port=2881 \
  --mysql-user=root@ebpf_tenant \
  --mysql-password='' \
  --mysql-db=test \
  --threads=1 \
  --events=1 \
  --table-name=sbtest1 \
  --table-size=10000 \
  --sql-output=uprobe/test/sysbench_generated.sql \
  prepare


# 运行测试
sysbench uprobe/test/sysbench_print_sql.lua \
  --mysql-host=7.27.43.145 \
  --mysql-port=2881 \
  --mysql-user=root@ebpf_tenant \
  --mysql-password='' \
  --mysql-db=test \
  --threads=1 \
  --events=10000 \
  --table-name=sbtest1 \
  --table-size=10000 \
  --sql-output=uprobe/test/sysbench_generated.sql \
  --time=0 \
  run

# 手动测试
# 手写sysbench风格的测试用例
# 在sysbench_audit_workload.sql中写测试用例

# 运行ebpf程序
./uprobe/bin/uprobe /home/yangshuo17/observer/bin/observer  0x000000000bf18950
# 批量执行sql
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_tenant -p'' --skip-ssl -Dtest < uprobe/test/sysbench_test/sysbench_generated.sql
./uprobe/bin/check_audit_sql audit_manu.dat uprobe/test/sysbench_test/sysbench_generated.sql
