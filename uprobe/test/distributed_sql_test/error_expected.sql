INSERT INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (1, 999, 'dup_primary_should_fail');
INSERT INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (9001, 100, 'dup_unique_should_fail');
UPDATE ebpf_audit_dist_test.dist_order SET not_existing_column = 1 WHERE order_id = 1;
SELECT * FROM ebpf_audit_dist_test.dist_not_existing_table;
SELECT id FROM ebpf_audit_dist_test.dist_range_case WHERE id = CAST('not_number' AS SIGNED);
DELETE FROM ebpf_audit_dist_test.dist_order WHERE order_id = -1;
