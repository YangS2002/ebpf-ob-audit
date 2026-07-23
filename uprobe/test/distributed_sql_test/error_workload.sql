-- 分布式 OB SQL 错误记录测试。
-- 执行前先执行 workload.sql 建表和种子数据。
-- 目标：验证跨分区/分布式执行失败时，ret_code、原始 query_sql、节点记录行为是否符合预期。

INSERT /* EBPF_DIST_ERR_DUP_PRIMARY */ INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (1, 999, 'dup_primary_should_fail');
INSERT /* EBPF_DIST_ERR_DUP_UNIQUE */ INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (9001, 100, 'dup_unique_should_fail');
UPDATE /* EBPF_DIST_ERR_BAD_COLUMN */ ebpf_audit_dist_test.dist_order SET not_existing_column = 1 WHERE order_id = 1;
SELECT /* EBPF_DIST_ERR_BAD_TABLE */ * FROM ebpf_audit_dist_test.dist_not_existing_table;
SELECT /* EBPF_DIST_ERR_BAD_PARTITION_EXPR */ id FROM ebpf_audit_dist_test.dist_range_case WHERE id = CAST('not_number' AS SIGNED);
DELETE /* EBPF_DIST_ERR_NO_MATCH */ FROM ebpf_audit_dist_test.dist_order WHERE order_id = -1;
