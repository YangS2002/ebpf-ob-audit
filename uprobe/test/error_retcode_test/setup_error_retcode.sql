-- ret_code 非 0 测试环境准备脚本。
-- 执行用户：root@ebpf_audit_tenant_a。
-- 作用：创建测试库、测试表、种子数据、低权限用户 error_limited_user。

-- 创建专用测试库，避免污染其他测试库。
CREATE DATABASE IF NOT EXISTS ebpf_audit_error_test;

-- 重建测试表，保证每次测试初始状态一致。
DROP TABLE IF EXISTS ebpf_audit_error_test.error_audit_case;
CREATE TABLE ebpf_audit_error_test.error_audit_case (
  id INT NOT NULL,
  k INT NOT NULL,
  c VARCHAR(120) NOT NULL,
  PRIMARY KEY (id)
);

-- 插入种子行，供权限不足 UPDATE/DELETE 用例命中目标行。
INSERT INTO ebpf_audit_error_test.error_audit_case (id, k, c) VALUES (1, 10, 'seed');

-- 重建低权限用户。该用户只授予 SELECT，后续 DML 应返回权限错误。
DROP USER IF EXISTS error_limited_user;
CREATE USER error_limited_user IDENTIFIED BY '';
GRANT SELECT ON ebpf_audit_error_test.error_audit_case TO error_limited_user;
