INSERT INTO ebpf_audit_error_test.error_audit_case (id, k, c) VALUES (2, 20, 'permission_denied_insert');
UPDATE ebpf_audit_error_test.error_audit_case SET k = 21 WHERE id = 1;
DELETE FROM ebpf_audit_error_test.error_audit_case WHERE id = 1;
SELEC * FROM ebpf_audit_error_test.error_audit_case;
INSERT INTO ebpf_audit_error_test.error_audit_case (id, k, c VALUES (3, 30, 'syntax_error_insert');
UPDATE ebpf_audit_error_test.error_audit_case SET WHERE id = 1;
SELECT SLEEP(1);
