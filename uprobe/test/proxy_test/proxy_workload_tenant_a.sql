INSERT INTO ebpf_audit_db_a1.identity_audit_case (id, k, c) VALUES (3, 50, 'tenant_a_proxy_db_a1_insert');
SELECT id, k, c FROM ebpf_audit_db_a1.identity_audit_case WHERE id = 3;
UPDATE ebpf_audit_db_a1.identity_audit_case SET k = 51, c = 'tenant_a_proxy_db_a1_update' WHERE id = 3;
DELETE FROM ebpf_audit_db_a1.identity_audit_case WHERE id = 3;
INSERT INTO ebpf_audit_db_a2.identity_audit_case (id, k, c) VALUES (3, 60, 'tenant_a_proxy_db_a2_insert');
SELECT id, k, c FROM ebpf_audit_db_a2.identity_audit_case WHERE id = 3;
UPDATE ebpf_audit_db_a2.identity_audit_case SET k = 61, c = 'tenant_a_proxy_db_a2_update' WHERE id = 3;
DELETE FROM ebpf_audit_db_a2.identity_audit_case WHERE id = 3;
