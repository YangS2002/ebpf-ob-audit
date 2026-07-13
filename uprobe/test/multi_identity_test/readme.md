# 多用户/代理用户/租户/库 SQL audit 测试

目标：验证不同 `tenant_name/user_name/proxy_user_name/db_name` 下的 `SELECT/INSERT/UPDATE/DELETE` 都能被采集，并可用 `check_audit_sql` 校验 SQL 是否完整。

## 文件

- `multi_identity_workload.sql`：完整 workload，包含租户、库、用户、表准备，以及所有 DML。
- `expected_audit_sql.sql`：只包含需要检查的 DML，供 `check_audit_sql` 使用。

## 连接执行

OceanBase 不支持在同一个 SQL 文件中切换连接用户/租户。按下面顺序执行对应片段：

### 1. sys 租户 root 准备租户

执行 `multi_identity_workload.sql` 开头资源单元、资源池、租户创建部分。

```bash
mysql -h 7.27.43.145 -P2881 -uroot@sys -p'' --skip-ssl
```

### 2. tenant_a root 准备库/表/用户，并执行 root 部分

```bash
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_a -p'' --skip-ssl
```

### 3. tenant_a 普通用户执行 user 部分

```bash
mysql -h 7.27.43.145 -P2881 -uaudit_user_a@ebpf_audit_tenant_a -p'' --skip-ssl
```

### 4. tenant_a 代理用户执行 proxy 部分

代理登录格式以当前集群配置为准，常见形式：

```bash
mysql -h 7.27.43.145 -P2881 -uaudit_user_a@ebpf_audit_tenant_a#proxy_user_a -p'' --skip-ssl
```

### 5. tenant_b 重复 root/user/proxy 部分

```bash
mysql -h 7.27.43.145 -P2881 -uroot@ebpf_audit_tenant_b -p'' --skip-ssl
mysql -h 7.27.43.145 -P2881 -uaudit_user_b@ebpf_audit_tenant_b -p'' --skip-ssl
mysql -h 7.27.43.145 -P2881 -uaudit_user_b@ebpf_audit_tenant_b#proxy_user_b -p'' --skip-ssl
```

## 检查

```bash
./uprobe/bin/check_audit_sql audit_identity.dat uprobe/test/multi_identity_test/expected_audit_sql.sql --print-matched
```

再转 CSV 验证身份字段：

```bash
./uprobe/bin/adt_to_csv audit_identity.dat audit_identity.csv all
```

重点看：

- `tenant_id`
- `user_id`
- `tenant_name`
- `user_name`
- `proxy_user_name`
- `db_name`
- `session_id`
- `trace_id`
