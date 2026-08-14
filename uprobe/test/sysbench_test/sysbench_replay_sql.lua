-- 从预生成的 SQL 文件顺序回放执行 (与 sysbench_print_sql.lua 配套)。
-- 生成阶段(离线,单线程)用 sysbench_print_sql.lua 的 run 导出 SQL 到文件;
-- 回放阶段用本脚本: thread_init 时一次性把文件读入内存, event() 全程只从内存
-- 取 SQL 执行, 不做任何写盘, 因此不影响压测性能。
--
-- 用法:
--   # 1) 离线生成 SQL 文件 (慢无所谓, 只跑一次)
--   sysbench uprobe/test/sysbench_test/sysbench_print_sql.lua \
--     --mysql-host=7.27.43.145 --mysql-port=2881 \
--     --mysql-user=root@ebpf_tenant --mysql-password='' --mysql-db=test \
--     --threads=1 --events=10000 --table-name=sbtest1 --table-size=10000 \
--     --sql-output=uprobe/test/sysbench_test/sysbench_generated.sql --time=0 run
--
--   # 2) 回放 (可多线程, 无写盘开销)
--   sysbench uprobe/test/sysbench_test/sysbench_replay_sql.lua \
--     --mysql-host=7.27.43.145 --mysql-port=2881 \
--     --mysql-user=root@ebpf_tenant --mysql-password='' --mysql-db=test \
--     --threads=8 --events=10000 \
--     --sql-input=uprobe/test/sysbench_test/sysbench_generated.sql run
--
-- 说明:
--   * 顺序回放: 每线程从文件第 1 条开始顺序执行, 到末尾回绕。
--   * --events / --time 控制回放总量; --events=0 且 --time>0 时按时长回放。
--   * 文件按行解析: 一行一条 SQL, 去掉行尾 ';' 与空白; 跳过空行和 '--' 注释行。
--   * 若文件由 prepare 导出会包含 DROP/CREATE, 回放前请用 run 导出(仅 DML), 或用
--     --skip-ddl=on 跳过 DDL 语句。

sysbench.cmdline.options = {
  sql_input = {"path to read SQL from (one statement per line)", "sysbench_generated.sql"},
  skip_ddl = {"skip DROP/CREATE/ALTER statements when replaying", false},
}

local drv = nil
local con = nil
local stmts = {}   -- 本线程内存中的 SQL 列表 (每线程独立 lua state)
local pos = 0      -- 本线程当前顺序位置

local function trim(s)
  return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

local function is_ddl(sql)
  local head = string.upper(string.sub(sql, 1, 6))
  return head:find("^DROP") or head:find("^CREATE") or head:find("^ALTER")
end

local function load_stmts()
  local path = sysbench.opt.sql_input
  local f, err = io.open(path, "r")
  if not f then
    error("failed to open sql input: " .. tostring(err))
  end
  local skip_ddl = sysbench.opt.skip_ddl
  for line in f:lines() do
    local s = trim(line)
    -- 跳过空行与注释行
    if s ~= "" and string.sub(s, 1, 2) ~= "--" then
      -- 去掉行尾分号
      s = (string.gsub(s, ";%s*$", ""))
      if s ~= "" and not (skip_ddl and is_ddl(s)) then
        stmts[#stmts + 1] = s
      end
    end
  end
  f:close()
  if #stmts == 0 then
    error("no SQL statements loaded from: " .. path)
  end
end

function thread_init(thread_id)
  drv = sysbench.sql.driver()
  con = drv:connect()
  load_stmts()
  pos = 0
end

function thread_done()
  if con then
    con:disconnect()
  end
end

function event()
  pos = pos + 1
  if pos > #stmts then
    pos = 1
  end
  con:query(stmts[pos])
end
