-- 分布式 OB SQL 记录测试 workload。
-- 目标：验证每台 OBServer 全量采集 + is_inner_sql 过滤后，用户级 SQL 在分布式执行场景下的记录情况。
-- 执行方式建议：所有 OBServer 同时启动采集；客户端分别连接不同 OBServer/OBProxy endpoint 执行本文件。

CREATE DATABASE IF NOT EXISTS ebpf_audit_dist_test;

DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_order_item;
DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_order;
DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_customer;
DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_range_case;
DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_tx_case;
DROP TABLE IF EXISTS ebpf_audit_dist_test.dist_unique_case;

CREATE TABLE ebpf_audit_dist_test.dist_customer (
  customer_id BIGINT NOT NULL,
  tenant_key BIGINT NOT NULL,
  name VARCHAR(120) NOT NULL,
  city VARCHAR(64) NOT NULL,
  status INT NOT NULL,
  PRIMARY KEY (customer_id),
  KEY idx_tenant_city (tenant_key, city)
) PARTITION BY HASH(customer_id) PARTITIONS 16;

CREATE TABLE ebpf_audit_dist_test.dist_order (
  order_id BIGINT NOT NULL,
  customer_id BIGINT NOT NULL,
  tenant_key BIGINT NOT NULL,
  amount DECIMAL(18,2) NOT NULL,
  order_status INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (order_id),
  KEY idx_customer (customer_id),
  KEY idx_tenant_status (tenant_key, order_status)
) PARTITION BY HASH(order_id) PARTITIONS 16;

CREATE TABLE ebpf_audit_dist_test.dist_order_item (
  item_id BIGINT NOT NULL,
  order_id BIGINT NOT NULL,
  sku VARCHAR(64) NOT NULL,
  qty INT NOT NULL,
  price DECIMAL(18,2) NOT NULL,
  PRIMARY KEY (item_id),
  KEY idx_order (order_id)
) PARTITION BY HASH(item_id) PARTITIONS 16;

CREATE TABLE ebpf_audit_dist_test.dist_range_case (
  id BIGINT NOT NULL,
  k BIGINT NOT NULL,
  c VARCHAR(120) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_k (k)
) PARTITION BY RANGE(id) (
  PARTITION p0 VALUES LESS THAN (1000),
  PARTITION p1 VALUES LESS THAN (2000),
  PARTITION p2 VALUES LESS THAN (3000),
  PARTITION p3 VALUES LESS THAN MAXVALUE
);

CREATE TABLE ebpf_audit_dist_test.dist_tx_case (
  id BIGINT NOT NULL,
  k BIGINT NOT NULL,
  c VARCHAR(120) NOT NULL,
  PRIMARY KEY (id)
) PARTITION BY HASH(id) PARTITIONS 16;

CREATE TABLE ebpf_audit_dist_test.dist_unique_case (
  id BIGINT NOT NULL,
  uk BIGINT NOT NULL,
  c VARCHAR(120) NOT NULL,
  PRIMARY KEY (id, uk),
  UNIQUE KEY uk_dist_unique_case (uk)
) PARTITION BY HASH(uk) PARTITIONS 16;

INSERT INTO ebpf_audit_dist_test.dist_customer (customer_id, tenant_key, name, city, status) VALUES
  (1, 10, 'dist_customer_1', 'hangzhou', 1),
  (2, 10, 'dist_customer_2', 'shanghai', 1),
  (1001, 20, 'dist_customer_1001', 'beijing', 1),
  (2001, 20, 'dist_customer_2001', 'shenzhen', 0),
  (3001, 30, 'dist_customer_3001', 'guangzhou', 1);

INSERT INTO ebpf_audit_dist_test.dist_order (order_id, customer_id, tenant_key, amount, order_status) VALUES
  (1, 1, 10, 11.00, 1),
  (2, 2, 10, 22.00, 1),
  (1001, 1001, 20, 1001.00, 2),
  (2001, 2001, 20, 2001.00, 3),
  (3001, 3001, 30, 3001.00, 1),
  (4001, 1, 10, 4001.00, 4);

INSERT INTO ebpf_audit_dist_test.dist_order_item (item_id, order_id, sku, qty, price) VALUES
  (1, 1, 'sku_1', 1, 11.00),
  (2, 2, 'sku_2', 2, 11.00),
  (1001, 1001, 'sku_1001', 1, 1001.00),
  (2001, 2001, 'sku_2001', 2, 1000.50),
  (3001, 3001, 'sku_3001', 3, 1000.33),
  (4001, 4001, 'sku_4001', 4, 1000.25);

INSERT INTO ebpf_audit_dist_test.dist_range_case (id, k, c) VALUES
  (1, 10, 'range_p0_1'),
  (1001, 20, 'range_p1_1001'),
  (2001, 30, 'range_p2_2001'),
  (3001, 40, 'range_p3_3001');

INSERT INTO ebpf_audit_dist_test.dist_tx_case (id, k, c) VALUES
  (1, 10, 'tx_seed_1'),
  (1001, 20, 'tx_seed_1001'),
  (2001, 30, 'tx_seed_2001');

INSERT INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES
  (1, 100, 'unique_seed_1'),
  (1001, 200, 'unique_seed_1001');

SELECT /* EBPF_DIST_POINT_SELECT_SINGLE_PARTITION */ customer_id, name, city FROM ebpf_audit_dist_test.dist_customer WHERE customer_id = 1;
SELECT /* EBPF_DIST_POINT_SELECT_REMOTE_CANDIDATE */ customer_id, name, city FROM ebpf_audit_dist_test.dist_customer WHERE customer_id = 3001;
SELECT /* EBPF_DIST_IN_LIST_MULTI_PARTITION */ customer_id, name FROM ebpf_audit_dist_test.dist_customer WHERE customer_id IN (1, 1001, 2001, 3001) ORDER BY customer_id;
SELECT /* EBPF_DIST_RANGE_MULTI_PARTITION */ id, k, c FROM ebpf_audit_dist_test.dist_range_case WHERE id BETWEEN 1 AND 3500 ORDER BY id;
SELECT /* EBPF_DIST_FULL_SCAN */ COUNT(*) FROM ebpf_audit_dist_test.dist_customer WHERE status >= 0;
SELECT /* EBPF_DIST_AGG_GROUP_BY */ tenant_key, COUNT(*), SUM(amount) FROM ebpf_audit_dist_test.dist_order GROUP BY tenant_key ORDER BY tenant_key;
SELECT /* EBPF_DIST_ORDER_LIMIT */ order_id, amount FROM ebpf_audit_dist_test.dist_order WHERE amount > 10 ORDER BY amount DESC LIMIT 3;
SELECT /* EBPF_DIST_DISTINCT */ DISTINCT tenant_key FROM ebpf_audit_dist_test.dist_order ORDER BY tenant_key;
SELECT /* EBPF_DIST_JOIN_HASH_PARTITIONED */ o.order_id, c.name, o.amount FROM ebpf_audit_dist_test.dist_order o JOIN ebpf_audit_dist_test.dist_customer c ON o.customer_id = c.customer_id WHERE o.order_id IN (1, 1001, 2001, 3001) ORDER BY o.order_id;
SELECT /* EBPF_DIST_JOIN_THREE_TABLE */ o.order_id, c.name, i.sku, i.qty FROM ebpf_audit_dist_test.dist_order o JOIN ebpf_audit_dist_test.dist_customer c ON o.customer_id = c.customer_id JOIN ebpf_audit_dist_test.dist_order_item i ON o.order_id = i.order_id WHERE o.tenant_key IN (10, 20, 30) ORDER BY o.order_id;
SELECT /* EBPF_DIST_SUBQUERY_EXISTS */ customer_id, name FROM ebpf_audit_dist_test.dist_customer c WHERE EXISTS (SELECT 1 FROM ebpf_audit_dist_test.dist_order o WHERE o.customer_id = c.customer_id AND o.amount > 1000) ORDER BY customer_id;
SELECT /* EBPF_DIST_SUBQUERY_IN */ order_id, amount FROM ebpf_audit_dist_test.dist_order WHERE customer_id IN (SELECT customer_id FROM ebpf_audit_dist_test.dist_customer WHERE status = 1) ORDER BY order_id;
SELECT /* EBPF_DIST_UNION_ALL */ customer_id AS id FROM ebpf_audit_dist_test.dist_customer WHERE customer_id IN (1, 2) UNION ALL SELECT order_id AS id FROM ebpf_audit_dist_test.dist_order WHERE order_id IN (1001, 2001);

UPDATE /* EBPF_DIST_POINT_UPDATE */ ebpf_audit_dist_test.dist_customer SET status = 2 WHERE customer_id = 1;
UPDATE /* EBPF_DIST_MULTI_PARTITION_UPDATE */ ebpf_audit_dist_test.dist_order SET order_status = order_status + 10 WHERE tenant_key IN (10, 20);
DELETE /* EBPF_DIST_POINT_DELETE */ FROM ebpf_audit_dist_test.dist_order_item WHERE item_id = 2;
DELETE /* EBPF_DIST_MULTI_PARTITION_DELETE */ FROM ebpf_audit_dist_test.dist_order_item WHERE order_id IN (1001, 2001);
INSERT /* EBPF_DIST_INSERT_SELECT */ INTO ebpf_audit_dist_test.dist_range_case (id, k, c) SELECT order_id + 5000, tenant_key, 'insert_select_from_order' FROM ebpf_audit_dist_test.dist_order WHERE order_id IN (1, 1001);
INSERT /* EBPF_DIST_UPSERT */ INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (2001, 200, 'unique_update_200') ON DUPLICATE KEY UPDATE c = VALUES(c);
REPLACE /* EBPF_DIST_REPLACE */ INTO ebpf_audit_dist_test.dist_unique_case (id, uk, c) VALUES (3001, 300, 'unique_replace_300');

BEGIN;
UPDATE /* EBPF_DIST_TX_UPDATE_P0 */ ebpf_audit_dist_test.dist_tx_case SET k = k + 1 WHERE id = 1;
UPDATE /* EBPF_DIST_TX_UPDATE_P1 */ ebpf_audit_dist_test.dist_tx_case SET k = k + 1 WHERE id = 1001;
INSERT /* EBPF_DIST_TX_INSERT_P2 */ INTO ebpf_audit_dist_test.dist_tx_case (id, k, c) VALUES (3001, 40, 'tx_insert_3001');
COMMIT;

BEGIN;
UPDATE /* EBPF_DIST_TX_ROLLBACK_UPDATE */ ebpf_audit_dist_test.dist_tx_case SET c = 'tx_rollback_should_not_persist' WHERE id = 2001;
ROLLBACK;

PREPARE ps_dist_point_select FROM 'SELECT customer_id, name FROM ebpf_audit_dist_test.dist_customer WHERE customer_id = ?';
SET @dist_customer_id = 1001;
EXECUTE ps_dist_point_select USING @dist_customer_id;
DEALLOCATE PREPARE ps_dist_point_select;

PREPARE ps_dist_multi_partition_range FROM 'SELECT id, k, c FROM ebpf_audit_dist_test.dist_range_case WHERE id BETWEEN ? AND ? ORDER BY id';
SET @dist_begin_id = 1, @dist_end_id = 3500;
EXECUTE ps_dist_multi_partition_range USING @dist_begin_id, @dist_end_id;
DEALLOCATE PREPARE ps_dist_multi_partition_range;

PREPARE ps_dist_update FROM 'UPDATE ebpf_audit_dist_test.dist_order SET order_status = order_status + ? WHERE tenant_key = ?';
SET @dist_delta = 1, @dist_tenant_key = 10;
EXECUTE ps_dist_update USING @dist_delta, @dist_tenant_key;
DEALLOCATE PREPARE ps_dist_update;

PREPARE ps_dist_join FROM 'SELECT o.order_id, c.name FROM ebpf_audit_dist_test.dist_order o JOIN ebpf_audit_dist_test.dist_customer c ON o.customer_id = c.customer_id WHERE o.amount > ? ORDER BY o.order_id';
SET @dist_amount = 1000;
EXECUTE ps_dist_join USING @dist_amount;
DEALLOCATE PREPARE ps_dist_join;

SELECT /* EBPF_DIST_FINAL_CUSTOMER */ customer_id, status FROM ebpf_audit_dist_test.dist_customer ORDER BY customer_id;
SELECT /* EBPF_DIST_FINAL_ORDER */ order_id, order_status FROM ebpf_audit_dist_test.dist_order ORDER BY order_id;
SELECT /* EBPF_DIST_FINAL_TX */ id, k, c FROM ebpf_audit_dist_test.dist_tx_case ORDER BY id;
