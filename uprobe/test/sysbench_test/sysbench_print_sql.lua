-- Sysbench-style workload that prints every executed SQL to a local file.
-- Usage:
--   sysbench uprobe/test/sysbench_print_sql.lua \
--     --mysql-host=7.27.43.145 \
--     --mysql-port=2881 \
--     --mysql-user=root@ebpf_tenant \
--     --mysql-password='password' \
--     --mysql-db=test \
--     --threads=1 \
--     --events=100 \
--     --table-name=sbtest1 \
--     --sql-output=uprobe/test/sysbench_generated.sql \
--     prepare
--
--   sysbench uprobe/test/sysbench_print_sql.lua \
--     --mysql-host=7.27.43.145 \
--     --mysql-port=2881 \
--     --mysql-user=root@ebpf_tenant \
--     --mysql-password='password' \
--     --mysql-db=test \
--     --threads=1 \
--     --events=100 \
--     --table-name=sbtest1 \
--     --sql-output=uprobe/test/sysbench_generated.sql \
--     run
--
--   sysbench uprobe/test/sysbench_print_sql.lua \
--     --mysql-host=7.27.43.145 \
--     --mysql-port=2881 \
--     --mysql-user=root@ebpf_tenant \
--     --mysql-password='password' \
--     --mysql-db=test \
--     --threads=1 \
--     --events=1 \
--     --table-name=sbtest1 \
--     --sql-output=uprobe/test/sysbench_generated.sql \
--     cleanup

sysbench.cmdline.options = {
  table_name = {"table name", "sbtest1"},
  table_size = {"number of rows prepared", 1000},
  range_size = {"range query size", 100},
  sql_output = {"path to save executed SQL", "sysbench_generated.sql"},
}

local drv = nil
local con = nil
local sql_file = nil
local thread_id_value = 0

local function quote_identifier(name)
  return "`" .. string.gsub(name, "`", "``") .. "`"
end

local function open_sql_file(mode)
  local file, err = io.open(sysbench.opt.sql_output, mode)
  if not file then
    error("failed to open sql output: " .. tostring(err))
  end
  return file
end

local function write_sql(sql)
  sql_file:write(sql)
  sql_file:write(";\n")
  sql_file:flush()
end

local function query(sql)
  write_sql(sql)
  return con:query(sql)
end

function thread_init(thread_id)
  thread_id_value = thread_id
  drv = sysbench.sql.driver()
  con = drv:connect()
  sql_file = open_sql_file("a")
end

function thread_done()
  if sql_file then
    sql_file:close()
  end
  if con then
    con:disconnect()
  end
end

function prepare()
  local table_name = quote_identifier(sysbench.opt.table_name)
  local table_size = tonumber(sysbench.opt.table_size)

  sql_file = open_sql_file("w")
  drv = sysbench.sql.driver()
  con = drv:connect()

  query("DROP TABLE IF EXISTS " .. table_name)
  query("CREATE TABLE " .. table_name .. " (" ..
        "id INT NOT NULL, " ..
        "k INT NOT NULL DEFAULT 0, " ..
        "c CHAR(120) NOT NULL DEFAULT '', " ..
        "pad CHAR(60) NOT NULL DEFAULT '', " ..
        "PRIMARY KEY (id), KEY k_1 (k))")

  for i = 1, table_size do
    local k = sysbench.rand.uniform(1, table_size)
    query(string.format("INSERT INTO %s (id, k, c, pad) VALUES (%d, %d, 'sysbench-c-%d', 'sysbench-pad-%d')",
                        table_name, i, k, i, i))
  end

  con:disconnect()
  sql_file:close()
end

function cleanup()
  local table_name = quote_identifier(sysbench.opt.table_name)

  sql_file = open_sql_file("a")
  drv = sysbench.sql.driver()
  con = drv:connect()

  query("DROP TABLE IF EXISTS " .. table_name)

  con:disconnect()
  sql_file:close()
end

function event()
  local table_name = quote_identifier(sysbench.opt.table_name)
  local table_size = tonumber(sysbench.opt.table_size)
  local range_size = tonumber(sysbench.opt.range_size)
  local id = sysbench.rand.uniform(1, table_size)
  local id2 = id + range_size
  local op = sysbench.rand.uniform(1, 10)

  if op == 1 then
    query(string.format("SELECT c FROM %s WHERE id = %d", table_name, id))
  elseif op == 2 then
    query(string.format("SELECT c FROM %s WHERE id BETWEEN %d AND %d", table_name, id, id2))
  elseif op == 3 then
    query(string.format("SELECT SUM(k) FROM %s WHERE id BETWEEN %d AND %d", table_name, id, id2))
  elseif op == 4 then
    query(string.format("SELECT c FROM %s WHERE id BETWEEN %d AND %d ORDER BY c", table_name, id, id2))
  elseif op == 5 then
    query(string.format("SELECT DISTINCT c FROM %s WHERE id BETWEEN %d AND %d ORDER BY c", table_name, id, id2))
  elseif op == 6 then
    query(string.format("UPDATE %s SET k = k + 1 WHERE id = %d", table_name, id))
  elseif op == 7 then
    query(string.format("UPDATE %s SET c = 'sysbench-updated-%d-%d' WHERE id = %d", table_name, thread_id_value, id, id))
  elseif op == 8 then
    query(string.format("DELETE FROM %s WHERE id = %d", table_name, id))
  elseif op == 9 then
    query(string.format("INSERT INTO %s (id, k, c, pad) VALUES (%d, %d, 'sysbench-reinsert-%d', 'sysbench-pad-%d') " ..
                        "ON DUPLICATE KEY UPDATE k = VALUES(k), c = VALUES(c), pad = VALUES(pad)",
                        table_name, id, sysbench.rand.uniform(1, table_size), id, id))
  else
    query(string.format("SELECT COUNT(*) FROM %s", table_name))
  end
end
