-- Sysbench-style audit workload with stable markers.
-- Usage:
--   mysql -h 7.27.43.145 -P2881 -uroot@ebpf_tenant -p'password' --skip-ssl -Dtest < uprobe/test/sysbench_audit_workload.sql
--
-- Workflow:
--   1. Manually start uprobe and save to an .adt file.
--   2. Run this SQL file with mysql/obclient.
--   3. Stop uprobe.
--   4. Run: ./uprobe/bin/check_audit_sql <adt-file> uprobe/test/sysbench_audit_workload.sql

CREATE DATABASE IF NOT EXISTS ebpf_audit_gtest;

/* EBPF_SYSBENCH_DROP_TABLE */ DROP TABLE IF EXISTS ebpf_audit_gtest.sbtest1;

/* EBPF_SYSBENCH_CREATE_TABLE */ CREATE TABLE ebpf_audit_gtest.sbtest1 (
  id INT NOT NULL,
  k INT NOT NULL DEFAULT 0,
  c CHAR(120) NOT NULL DEFAULT '',
  pad CHAR(60) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY k_1 (k)
);

/* EBPF_SYSBENCH_INSERT_1 */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (1, 10, 'EBPF_SYSBENCH_INSERT_1_C', 'pad_1');
/* EBPF_SYSBENCH_INSERT_2 */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (2, 20, 'EBPF_SYSBENCH_INSERT_2_C', 'pad_2');
/* EBPF_SYSBENCH_INSERT_3 */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (3, 30, 'EBPF_SYSBENCH_INSERT_3_C', 'pad_3');
/* EBPF_SYSBENCH_INSERT_4 */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (4, 40, 'EBPF_SYSBENCH_INSERT_4_C', 'pad_4');
/* EBPF_SYSBENCH_INSERT_5 */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (5, 50, 'EBPF_SYSBENCH_INSERT_5_C', 'pad_5');

/* EBPF_SYSBENCH_POINT_SELECT */ SELECT c FROM ebpf_audit_gtest.sbtest1 WHERE id = 3;
/* EBPF_SYSBENCH_SIMPLE_RANGE */ SELECT c FROM ebpf_audit_gtest.sbtest1 WHERE id BETWEEN 2 AND 4;
/* EBPF_SYSBENCH_SUM_RANGE */ SELECT SUM(k) FROM ebpf_audit_gtest.sbtest1 WHERE id BETWEEN 1 AND 5;
/* EBPF_SYSBENCH_ORDER_RANGE */ SELECT c FROM ebpf_audit_gtest.sbtest1 WHERE id BETWEEN 1 AND 5 ORDER BY c;
/* EBPF_SYSBENCH_DISTINCT_RANGE */ SELECT DISTINCT c FROM ebpf_audit_gtest.sbtest1 WHERE id BETWEEN 1 AND 5 ORDER BY c;

/* EBPF_SYSBENCH_UPDATE_INDEX */ UPDATE ebpf_audit_gtest.sbtest1 SET k = k + 1 WHERE id = 1;
/* EBPF_SYSBENCH_UPDATE_NON_INDEX */ UPDATE ebpf_audit_gtest.sbtest1 SET c = 'EBPF_SYSBENCH_UPDATE_NON_INDEX_C' WHERE id = 2;
/* EBPF_SYSBENCH_DELETE */ DELETE FROM ebpf_audit_gtest.sbtest1 WHERE id = 5;
/* EBPF_SYSBENCH_REINSERT */ INSERT INTO ebpf_audit_gtest.sbtest1 (id, k, c, pad) VALUES (5, 55, 'EBPF_SYSBENCH_REINSERT_C', 'pad_5_new');

/* EBPF_SYSBENCH_FINAL_COUNT */ SELECT COUNT(*) FROM ebpf_audit_gtest.sbtest1;
/* EBPF_SYSBENCH_FINAL_CHECK */ SELECT id, k, c FROM ebpf_audit_gtest.sbtest1 ORDER BY id;
