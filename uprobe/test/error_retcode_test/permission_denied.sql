-- 权限不足测试脚本。
-- 执行用户：error_limited_user@ebpf_audit_tenant_a。
-- 前提：先执行 setup_error_retcode.sql，该用户只有 SELECT 权限。
-- 执行方式必须加 mysql --force，避免第一条错误后客户端退出。

-- 预期失败：error_limited_user 没有 INSERT 权限，ret_code 应非 0。
INSERT INTO ebpf_audit_error_test.error_audit_case (id, k, c) VALUES (2, 20, 'permission_denied_insert');

-- 预期失败：error_limited_user 没有 UPDATE 权限，ret_code 应非 0。
UPDATE ebpf_audit_error_test.error_audit_case SET k = 21 WHERE id = 1;

-- 预期失败：error_limited_user 没有 DELETE 权限，ret_code 应非 0。
DELETE FROM ebpf_audit_error_test.error_audit_case WHERE id = 1;
