CREATE DATABASE IF NOT EXISTS ebpf_audit_ps_test;

DROP TABLE IF EXISTS ebpf_audit_ps_test.ps_audit_case;

CREATE TABLE ebpf_audit_ps_test.ps_audit_case (
  id INT NOT NULL,
  k INT NOT NULL,
  c VARCHAR(120) NOT NULL,
  pad VARCHAR(60) NOT NULL,
  PRIMARY KEY (id),
  KEY k_1 (k)
);

PREPARE ps_insert FROM 'INSERT INTO ebpf_audit_ps_test.ps_audit_case (id, k, c, pad) VALUES (?, ?, ?, ?)';
SET @id = 1, @k = 10, @c = 'ps_insert_c_1', @pad = 'ps_pad_1';
EXECUTE ps_insert USING @id, @k, @c, @pad;
SET @id = 2, @k = 20, @c = 'ps_insert_c_2', @pad = 'ps_pad_2';
EXECUTE ps_insert USING @id, @k, @c, @pad;
DEALLOCATE PREPARE ps_insert;

PREPARE ps_point_select FROM 'SELECT c FROM ebpf_audit_ps_test.ps_audit_case WHERE id = ?';
SET @id = 1;
EXECUTE ps_point_select USING @id;
DEALLOCATE PREPARE ps_point_select;

PREPARE ps_range_select FROM 'SELECT id, k, c FROM ebpf_audit_ps_test.ps_audit_case WHERE id BETWEEN ? AND ? ORDER BY id';
SET @begin_id = 1, @end_id = 2;
EXECUTE ps_range_select USING @begin_id, @end_id;
DEALLOCATE PREPARE ps_range_select;

PREPARE ps_update FROM 'UPDATE ebpf_audit_ps_test.ps_audit_case SET k = k + ? WHERE id = ?';
SET @delta = 5, @id = 1;
EXECUTE ps_update USING @delta, @id;
DEALLOCATE PREPARE ps_update;

PREPARE ps_delete FROM 'DELETE FROM ebpf_audit_ps_test.ps_audit_case WHERE id = ?';
SET @id = 2;
EXECUTE ps_delete USING @id;
DEALLOCATE PREPARE ps_delete;

PREPARE ps_count FROM 'SELECT COUNT(*) FROM ebpf_audit_ps_test.ps_audit_case';
EXECUTE ps_count;
DEALLOCATE PREPARE ps_count;
