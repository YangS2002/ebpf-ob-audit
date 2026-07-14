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
