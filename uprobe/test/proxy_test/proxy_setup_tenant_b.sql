-- 在 tenant_b 中用 root 执行，创建代理测试用户和授权。
CREATE USER IF NOT EXISTS audit_user_b IDENTIFIED BY '';
CREATE USER IF NOT EXISTS proxy_user_b IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON ebpf_audit_db_b1.* TO audit_user_b;
GRANT ALL PRIVILEGES ON ebpf_audit_db_b2.* TO audit_user_b;
GRANT ALL PRIVILEGES ON ebpf_audit_db_b1.* TO proxy_user_b;
GRANT ALL PRIVILEGES ON ebpf_audit_db_b2.* TO proxy_user_b;
GRANT PROXY ON audit_user_b TO proxy_user_b;
