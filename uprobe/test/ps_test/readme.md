# PS 协议 SQL 审计测试

本目录用于测试 SQL PREPARE/EXECUTE 形态下的审计记录是否完整落盘。

## 文件

- `ps_workload.sql`：执行用 workload，包含建库、建表、`PREPARE`、`SET`、`EXECUTE`、`DEALLOCATE`。
- `expected_audit_sql.sql`：期望在 `.adt` 记录中出现的 SQL，供 `check_audit_sql` 检查。

## 执行流程

1. 启动 uprobe，输出到 `audit_ps.dat`。

```bash
./uprobe/bin/uprobe /path/to/observer <offset> audit_ps.dat
```

2. 执行 PS workload。

```bash
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_tenant -p'' --skip-ssl -Dtest \
  < uprobe/test/ps_test/ps_workload.sql
```

3. 停止 uprobe。

4. 检查记录。

```bash
./uprobe/bin/check_audit_sql audit_ps.dat uprobe/test/ps_test/expected_audit_sql.sql
```

需要打印匹配到的记录：

```bash
./uprobe/bin/check_audit_sql audit_ps.dat uprobe/test/ps_test/expected_audit_sql.sql --print-matched
```

## 注意

这里使用的是 SQL 层面的 `PREPARE/EXECUTE`，不是 C API 的 `mysql_stmt_prepare/mysql_stmt_execute` 二进制 PS 协议。
如果要测试真正二进制 PS，需要另写一个使用 MySQL C API 的客户端程序。
