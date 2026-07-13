INSERT INTO ebpf_audit_db_b1.identity_audit_case (id, k, c) VALUES (3, 110, 'tenant_b_proxy_db_b1_insert');
SELECT id, k, c FROM ebpf_audit_db_b1.identity_audit_case WHERE id = 3;
UPDATE ebpf_audit_db_b1.identity_audit_case SET k = 111, c = 'tenant_b_proxy_db_b1_update' WHERE id = 3;
DELETE FROM ebpf_audit_db_b1.identity_audit_case WHERE id = 3;
INSERT INTO ebpf_audit_db_b2.identity_audit_case (id, k, c) VALUES (3, 120, 'tenant_b_proxy_db_b2_insert');
SELECT id, k, c FROM ebpf_audit_db_b2.identity_audit_case WHERE id = 3;
UPDATE ebpf_audit_db_b2.identity_audit_case SET k = 121, c = 'tenant_b_proxy_db_b2_update' WHERE id = 3;
DELETE FROM ebpf_audit_db_b2.identity_audit_case WHERE id = 3;
