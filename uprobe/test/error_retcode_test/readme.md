# ret_code 非 0 审计测试

目标：验证权限不足、语法错误、超时 SQL 被审计记录捕获，并且 `ret_code != 0`。

## 文件

- `setup_error_retcode.sql`：root 准备库、表、低权限用户。
- `permission_denied.sql`：低权限用户执行 `INSERT/UPDATE/DELETE`，预期权限错误。
- `syntax_error.sql`：root 执行语法错误 SQL，预期语法错误。
- `timeout_error.sql`：root 设置极短超时并执行慢 SQL，预期超时。
- `expected_error_sql.sql`：期望捕获的失败 SQL。

## 执行

准备：

```bash
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_a -p'' --skip-ssl < uprobe/test/error_retcode_test/setup_error_retcode.sql
```

开启探针后执行失败 SQL。用 `--force`，避免 mysql 遇到错误直接退出：

```bash
mysql --force -h 7.27.43.145 -P2881 -uerror_limited_user@ebpf_audit_tenant_a -p'' --skip-ssl < uprobe/test/error_retcode_test/permission_denied.sql
mysql --force -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_a -p'' --skip-ssl < uprobe/test/error_retcode_test/syntax_error.sql
mysql --force -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_a -p'' --skip-ssl < uprobe/test/error_retcode_test/timeout_error.sql
```

## 检查 SQL 是否留存

```bash
./uprobe/bin/check_audit_sql audit_error.dat uprobe/test/error_retcode_test/expected_error_sql.sql --print-matched
```

## 检查 ret_code

转 CSV：

```bash
./uprobe/bin/adt_to_csv audit_error.dat audit_error.csv all
```

查看这些 SQL 对应记录：

```bash
python3 - <<'PY'
import csv
cases = [
    'permission_denied_insert',
    'SET k = 21 WHERE id = 1',
    'DELETE FROM ebpf_audit_error_test.error_audit_case WHERE id = 1',
    'SELEC * FROM ebpf_audit_error_test.error_audit_case',
    'syntax_error_insert',
    'UPDATE ebpf_audit_error_test.error_audit_case SET WHERE id = 1',
    'SELECT SLEEP(1)',
]
with open('audit_error.csv', newline='') as f:
    for row in csv.DictReader(f):
        sql = row.get('query_sql', '')
        if any(c in sql for c in cases):
            print(row['ret_code'], row.get('stmt_type_name', row.get('stmt_type')), row.get('trans_status_name', row.get('trans_status')), sql)
PY
```

期望：以上失败 SQL 均有记录，且 `ret_code` 不等于 `0`。
