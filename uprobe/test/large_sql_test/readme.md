# 运行ebpf程序
./uprobe/bin/uprobe /home/yangshuo17/observer/bin/observer  0x000000000bf18950
# 批量执行sql
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_a -p'' --skip-ssl -Dtest < /home/yangshuo17/ebpf-ob-audit/uprobe/test/large_sql_test/large_sql_workload.sql

./uprobe/bin/check_audit_sql audit_ps.dat uprobe/test/large_sql_test/expected_large_sql.sql--print-matched