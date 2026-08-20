# Audit 字段扩展指南

本项目的审计数据链路分三层：

1. `uprobe/src/uprobe.bpf.c`：eBPF 程序，从 OceanBase `ObAuditRecordData` 内存偏移读取字段。
2. `uprobe/src/uprobe.h`：生产端和消费端共享的二进制 `struct event` 定义。
3. `uprobe/tools/adt_to_csv.cpp`：消费 `.adt` 二进制文件并格式化为 CSV。

`.adt` 文件存储始终是二进制 `struct event`，不要在 eBPF 里写格式化字符串。枚举名、IP、trace id 等人类可读格式只在 `adt_to_csv` 中生成。

## 新增一个采集字段

假设要新增 OceanBase audit 字段 `request_type_`。

### 1. 在 `uprobe.h` 增加偏移

```c
#define OB_AUDIT_REQUEST_TYPE_OFF <offset>
```

偏移必须来自当前 observer 二进制对应的 `ObAuditRecordData` 布局。不同 OceanBase 版本可能不同。

### 2. 在 `struct event` 末尾追加字段

```c
struct event {
    ...
    int request_type;
};
```

优先追加到末尾，避免改变已有字段顺序。不要在中间插入，除非准备处理旧文件兼容问题。

### 3. 在 `uprobe.bpf.c` 读取字段

选择匹配类型的 helper：

```c
read_i32(audit_record, OB_AUDIT_REQUEST_TYPE_OFF, &e->request_type);
```

字符串字段使用已有字符串读取 helper；地址字段使用 `read_addr_field`。BPF verifier 对动态长度敏感，不要随意改通用读取逻辑。

### 4. 在 `adt_to_csv.cpp` 增加 CSV 输出

新增 writer：

```c
DEFINE_I32_FIELD_WRITER(write_request_type, request_type)
```

然后在 `CSV_FIELDS` 加一项：

```c
{"request_type", write_request_type},
```

CSV header 和 row 都由 `CSV_FIELDS` 生成，不要再手写两份列表。

## 新增一个只在 CSV 中格式化的派生字段

比如已有 `request_type` 数字字段，要输出 `request_type_name`。

### 1. 增加格式化函数

可以放在 `uprobe/tools/audit_format.h`：

```c
static inline const char *request_type_to_string(int request_type)
{
    switch (request_type) {
    case 1: return "...";
    default: return "UNKNOWN";
    }
}
```

### 2. 在 `adt_to_csv.cpp` 增加 writer

```c
static void write_request_type_name(FILE *out, const event &e)
{
    write_csv_string(out, request_type_to_string(e.request_type));
}
```

### 3. 在 `CSV_FIELDS` 加一项

```c
{"request_type_name", write_request_type_name},
```

这不会改变 `.adt` 二进制结构。

## 让新字段上送到 MongoDB（collector 链路）

上面的步骤只让字段进入 `.adt` 和 `adt_to_csv`。当前主链路是 `agent -> gRPC -> collector -> MongoDB`，collector 侧是 **schema 驱动**的，还需要额外两处修改。

数据流：`struct event` 二进制原样上送 collector，collector 按 `audit_schema.json` 决定写哪些字段、用什么数字键落库。

- `uprobe/audit_schema.json`：数字键 → 字段全名 的映射，带 `version`。每条记录落库时带 `sv=version` 标记，下游按 sv 解码。
- `uprobe/src/mongodb_sink.cpp` 的 `kFieldAppenders[]`：字段全名 → "如何从 `struct event` 取值写进 BSON" 的 writer 注册表。

**硬约束**：collector 启动时遍历 `audit_schema.json` 的每个字段全名去 `kFieldAppenders` 找 writer；只要 schema 里出现某字段、而注册表里没有对应 writer，collector 会启动失败并报 `schema field has no writer support: <字段名>`。所以这两处必须成对新增。

前置：先完成上面《新增一个采集字段》的步骤（`uprobe.h` 偏移 + `struct event` 追加 + `uprobe.bpf.c` 读取），保证 `struct event` 里已有该字段。

### 1. 在 `mongodb_sink.cpp` 的 `kFieldAppenders` 增加 writer

按字段类型选 BSON 追加方式（appender 是无捕获 lambda，`c.e` 是 `const event *`）：

```cpp
// 整型
{"request_type", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, c.e->request_type); }},
// 字符串（带长度的采集字段用 append_text）
{"some_name", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_some_name(c.e), c.e->some_name_len); }},
```

非 `event` 派生的字段（如 `agent_id` / `server_ip` / `ingest_time`）从 `append_ctx` 取，参考现有同名项。

### 2. 在 `audit_schema.json` 增加映射并递增 `version`

```json
{
  "version": 3,
  "fields": {
    "...": "...",
    "47": "request_type"
  }
}
```

用未占用的数字键；`version` 必须递增（记录会带新 `sv`，schema 字典集合按版本写入，下游按 sv 解码）。

**只能增量，绝不复用/重编号/删除已有数字键。** MongoDB 里字段以数字键存储（如 `{"37": "root"}`），键的含义完全由 schema 版本决定。若改动某个已有键的映射，历史记录里那个键会被按新含义解码，值直接张冠李戴。新增字段永远只往后追加新键。

### 3. 派生 / 格式化字段（可选）

若要落库枚举名或格式化值（如 `plan_type_value` + `plan_type`、`trans_status_value` + `trans_status`），在 `kFieldAppenders` 里加一项调用格式化函数写字符串，并在 `audit_schema.json` 里给它单独的数字键，参考现有 `plan_type` / `trans_status` 两项写法。

### 4. 对比校验（可选）

若要把新字段纳入与官方 `GV$OB_SQL_AUDIT` 的正确性对比：

- `uprobe/tools/mongo_to_csv.py`：确认新字段能导出（按数字键或全名）。
- `uprobe/test/distributed_sql_test/compare_official_collector.py`：在 `COMPARE_FIELDS` 增加该字段。

## 版本和兼容

`audit_file_header` 里记录：

- `version`
- `header_size`
- `event_size`

消费端会检查：

```c
header.event_size == sizeof(event)
```

因此只要 `struct event` 大小变化，旧工具读取新文件或新工具读取旧文件都可能失败。这是当前设计的显式保护。

规则：

- 只新增 CSV 派生字段：不改 `struct event`，不用改 `AUDIT_FILE_VERSION`。
- 新增采集字段并改变 `struct event` 大小：建议递增 `AUDIT_FILE_VERSION`，并确保生产端和消费端一起升级。
- 修改已有字段含义、类型、顺序：必须递增 `AUDIT_FILE_VERSION`，并评估是否需要兼容旧文件。

## 修改检查清单

新增采集字段时检查：

- [ ] `uprobe/src/uprobe.h` 增加 `OB_AUDIT_*_OFF`
- [ ] `uprobe/src/uprobe.h` 在 `struct event` 末尾追加字段
- [ ] `uprobe/src/uprobe.bpf.c` 读取字段到 `event`
- [ ] `uprobe/tools/adt_to_csv.cpp` 增加 writer
- [ ] `uprobe/tools/adt_to_csv.cpp` 在 `CSV_FIELDS` 增加列
- [ ] 如需格式化，`uprobe/tools/audit_format.h` 增加转换函数
- [ ] 判断是否需要递增 `AUDIT_FILE_VERSION`
- [ ] 重新编译生产端和消费端

要让新字段上送到 MongoDB，额外检查（否则 collector 启动会因缺 writer 失败）：

- [ ] `uprobe/src/mongodb_sink.cpp` 在 `kFieldAppenders` 增加 writer
- [ ] `uprobe/audit_schema.json` 增加数字键映射
- [ ] `uprobe/audit_schema.json` 递增 `version`
- [ ] 重新编译并重新部署 collector
- [ ] 如需对比校验：`mongo_to_csv.py` 导出 + `compare_official_collector.py` 的 `COMPARE_FIELDS`

只新增 CSV 派生字段时检查：

- [ ] `uprobe/tools/audit_format.h` 增加转换函数（如需要）
- [ ] `uprobe/tools/adt_to_csv.cpp` 增加 writer
- [ ] `uprobe/tools/adt_to_csv.cpp` 在 `CSV_FIELDS` 增加列
- [ ] 不修改 `struct event`
- [ ] 不修改 eBPF 程序

## 验证

编译工具：

```bash
make -C uprobe tools
```

转换样例：

```bash
./uprobe/bin/adt_to_csv audit.dat audit.csv all
```

检查 CSV 列数是否一致：

```bash
python3 - <<'PY'
import csv
with open('audit.csv', newline='') as f:
    rows = csv.reader(f)
    header = next(rows)
    for idx, row in enumerate(rows, 2):
        if len(row) != len(header):
            raise SystemExit(f'line {idx}: columns={len(row)} header={len(header)}')
print('csv columns ok')
PY
```
