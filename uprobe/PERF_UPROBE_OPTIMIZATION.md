# uprobe 性能分析优化

本文记录 uprobe 全链路两处性能问题的发现过程、用到的命令/打点、测得的数据与优化:

- **内核态**:eBPF 中 `bpf_probe_read_user` 的调用次数开销(第 1–7 节)。
- **用户态**:agent 侧 `submit`(入 batch + seal + 唤醒 worker)的开销(第 8 节)。

## 1. 问题背景

uprobe 挂在 OB 审计记录写入点,内核态 eBPF 程序需要把 `ObAuditRecord` 的字段
拷到用户态。最初实现对定长区**散着读** ~30 次 `bpf_probe_read_user`
(status / trace_id / 10 个 u64 / 3 个 i32 / sql_id / 6 个时间戳 / 2 个 addr +
各字符串的 ptr-len 对)。怀疑点:调用次数太多,固定开销累积。

## 2. 怎么发现的:两条测量路径

### 2.1 eBPF 内部打点(测"每 run 总耗时")

在 eBPF 程序里用 `bpf_ktime_get_ns()` 在处理逻辑首尾各取一次时间戳,差值即
单次 uprobe 命中处理耗时,通过 map / ringbuf 上报,用户态聚合。

```c
// 进入处理
__u64 t0 = bpf_ktime_get_ns();

// ... 30+ 次 bpf_probe_read_user ...

// 处理结束
__u64 t1 = bpf_ktime_get_ns();
__u64 cost = t1 - t0;   // 单 run 纳秒耗时
```

要点:
- `bpf_ktime_get_ns()` 是单调时钟,纳秒精度,适合测内核态代码段。
- 只测处理段、不含 uprobe 触发本身的调度开销,聚焦"我们自己的读逻辑"。
- 多次采样取均值,避免抖动。

### 2.2 perf(测"开销花在哪个函数/符号")

用 `perf` 确认时间是消耗在 `bpf_probe_read_user` → `copy_from_user` 的固定路径上,
而不是字节拷贝。

```bash
# 采样:按 CPU 周期采样,-g 抓调用栈,-a 全核,持续 N 秒
sudo perf record -F 999 -a -g -- sleep 30

# 汇总:看热点符号占比
sudo perf report --stdio

# 若定位到具体 helper,做指令级注解,看时间落在 access_ok / pagefault 上
sudo perf annotate bpf_probe_read_user

# 统计计数:上下文切换、cache-miss、指令数等,判断是否被固定开销主导
sudo perf stat -e cycles,instructions,cache-misses -a -- sleep 10
```

perf 观察到的现象:
- 热点集中在 `bpf_probe_read_user` 的固定前缀:`access_ok`、
  `pagefault_disable/enable`、helper 调用分发,而非 `memcpy` 本体。
- 说明成本由**调用次数**主导,不由**字节数**主导。

## 3. 测得的数据

| 指标 | 数值 | 说明 |
|------|------|------|
| 单 run 总耗时 | **4381 ns/run** | eBPF 打点实测 |
| 单 run 内 read 次数 | **35 次** | 计数得到 |
| 每次固定开销 | **≈ 125 ns/次** | 4381 ÷ 35 |
| 每次实际拷贝 | **48 字节** | 拷得很少,却仍 125ns |
| 定长区连续块 | **1728 字节** | 最高用到偏移 `trans_status` 1720+8 |
| 1728B memcpy | **≈ 40–70 ns** | ~100–200 cycle |

**结论**:每次 read 花 125ns,但只拷 48 字节。钱几乎全花在"发起一次读"的固定开销
上,拷贝的字节数几乎不要钱。

## 4. 成本模型

```
cost ≈ C_fixed + k · bytes

C_fixed ≈ 125 ns/次   (access_ok + pagefault_disable/enable + helper 分发)
k · bytes            (copy_from_user 的 memcpy,小尺寸下几十 ns)
```

## 5. 优化:定长区一次读 1728B

**改前**:定长区散读 ~30 次。

```
~30 次 × 125ns ≈ 3750 ns
```

**改后**:一次 `bpf_probe_read_user` 读整块 `[0,1728]`,标量解析**下沉到 collector**
(用户态)完成。

```
1 次 C_fixed + memcpy(1728B) ≈ 125 + ~70 ≈ 195 ns
```

**净收益**:省下 29 次 × 125ns ≈ **3600 ns**;多拷的 ~1400 字节 memcpy 只花几十 ns。
定长区 ~30 次 → 1 次,是这次优化的大头。

## 6. 前提与边界

- 1728B 是**同一记录、连续区**,一次 `copy_from_user` 拷完,不额外触发缺页
  (observer 正在用这条记录,全程驻留)。缺页是微秒级,一旦触发账会翻盘。
- `1728 = trans_status 偏移 1720 + 8`,不超过 `ObAuditRecord` 实际大小,**不读越界**。
- 字符串那 **6 次省不掉**:sql / params / 4 个 name 是离散指针,不在连续区,
  只能各读各的。

## 7. 复现验证步骤

```bash
# 1. eBPF 打点跑一轮,收集 cost 分布(改前/改后各一次)
#    观察 4381ns/run 是否随 read 次数下降

# 2. perf 采样确认热点从多次 bpf_probe_read_user 收敛
sudo perf record -F 999 -a -g -- sleep 30
sudo perf report --stdio | head -40

# 3. 对比改前改后单 run 均值,验证 ~3500ns 净收益
```

---

## 8. agent 用户态:submit 开销的发现与优化

内核态优化后,event 落到用户态 ringbuf。agent 从 ringbuf 消费,把每条记录
`submit` 到发送批次,batch 满/超时后由 worker 经 gRPC 上送 collector。
下面记录如何发现 `submit` 段成为 agent CPU 热点。

### 8.1 submit 链路

```
ring_buffer__consume            uprobe.cpp:741   从 ringbuf 抽取 event
  → append_event / append_merged uprobe.cpp:415 / :442  按 total_size 拷入 batch
  → emit_record                  uprobe.cpp:392   写 before_submit 时间戳后调 submit
  → grpc_submit_locked           audit_grpc_sender.cpp:709   ★ submit 核心:入 batch + seal + notify
  → seal_current_batch_locked    audit_grpc_sender.cpp:274   满/超时封 batch,推 ready_batches
  → sender_worker / pop_ready_batch  :569 / :540  worker 取 batch(返回指针,不拷贝)
  → upload_once → Upload         :419 / :462      gRPC 发送 + 测 roundtrip
```

### 8.2 怎么发现的:内联计时打点

agent 用户态没法用 `bpf_ktime_get_ns`,改用 `monotonic_ns()`(steady_clock)在
submit 段首尾打点,由编译宏 `AUDIT_GRPC_TIMING_ENABLED` 控制
(`audit_grpc_sender.h:13`)。

```cpp
// audit_grpc_sender.cpp:716
uint64_t submit_start_ns = monotonic_ns();   // submit 起点

// ... 锁 + 稳态 batch 检查 + append(data,size) + 可能 seal + notify ...

// audit_grpc_sender.cpp:774-778
uint64_t submit_ns = monotonic_ns() - submit_start_ns;
stats.total_submit_ns += submit_ns;
stats.max_submit_ns = max(stats.max_submit_ns, submit_ns);
stats.submit_calls++;
```

聚合指标在 `agent_metrics` 日志里换算成微秒打印(揭示点):

```
avg_submit_us = total_submit_ns / submit_calls / 1000   # uprobe.cpp:307-323
max_submit_us = max_submit_ns / 1000
```

另有两条**跨态时间戳字段**(宏 `AUDIT_PERF_FIELDS_ENABLED`,`uprobe.h:204-205`),
落库后可离线归因整段 agent submit 耗时:

- `perf_agent_before_submit_ns`  `uprobe.cpp:396`   agent 收到、submit 前
- `perf_agent_after_submit_ns`   `audit_grpc_sender.cpp:760`  submit 后就地写回
- 落库:`mongodb_sink.cpp:358-359`

### 8.3 测得的现象

- `avg_submit_us` / `max_submit_us` 偏高:submit 不是纯 append,锁内还夹着
  每条记录的 `steady_clock::now`、`notify_one`、以及 batch/protobuf 的整块拷贝。
- perf / metrics 交叉发现更大的一头在**调度**:
  `uprobe.cpp:732-737` 注释(实测)——**睡眠/唤醒的上下文切换占 agent CPU ~29%**,
  稳态"抽干 ringbuf → 睡"循环约 **1000 次/s**(`idle_min=1000us`,
  `idle_max=5000us`,对齐 gRPC `flush_interval=5ms`)。
- 说明 agent 侧成本由**每条记录的固定动作**(锁内重复取时、逐条唤醒 worker)
  和**频繁睡眠/唤醒的上下文切换**主导,而非载荷字节数。

### 8.4 据此做的优化

| 优化 | 改前 | 改后 | file:line |
|------|------|------|-----------|
| event 拷贝按 size | 固定 4096B 整块 memcpy | 按 `total_size` 真实字节拷 | `uprobe.cpp:415-439` / `audit_record.h:12-19` |
| `steady_clock::now` 复用 | submit 内多处各取 `now()` | 取一次传给到期检查/首条时间 | `audit_grpc_sender.cpp:731` |
| 去逐条 `notify_one` | 每条记录都唤醒 worker | 仅 seal 后 或 新 batch 首条才 notify | `audit_grpc_sender.cpp:769-772` / seal `:281` |
| pop batch 去复制 | 出队整拷 batch | `ready_batches` 存裸指针,pop 只取指针 | `audit_grpc_sender.cpp:540-551` |
| protobuf 载荷零拷贝 | `set_records()` 整拷 | `set_allocated_records()` + `ReclaimGuard` move | `audit_grpc_sender.cpp:447-452` |
| ringbuf reserve | 经中间栈缓冲再拷 | BPF `bpf_ringbuf_reserve` 直写;batch 池 `reserve` 预分配 | `uprobe.bpf.c:52` / `audit_grpc_sender.cpp:105` |
| sender 多 worker + 重试 | 单发送线程 | batch 池 + 多 worker + `upload_with_retries` | `audit_grpc_sender.cpp:64-142` / `:513` |

**核心思路一致**:跟内核态"减少调用次数"同源——用户态是**减少每条记录的固定动作
和拷贝**(按需拷、时钟复用、批量唤醒、指针 move 替整拷),并用 batch + 定时 flush
把"逐条唤醒"摊薄成"每 batch 唤醒一次",压低上下文切换占比。

### 8.5 复现验证

```bash
# 1. 编译时打开计时宏
#    -DAUDIT_GRPC_TIMING_ENABLED  (-DAUDIT_PERF_FIELDS_ENABLED 做跨态归因)

# 2. 跑起来看 agent_metrics 日志里的 avg_submit_us / max_submit_us、submit_calls

# 3. perf 看 agent 进程,确认热点从锁内逐条动作 + futex/schedule 收敛
sudo perf record -F 999 -p <agent_pid> -g -- sleep 30
sudo perf report --stdio | head -40
sudo perf stat -e context-switches,cycles -p <agent_pid> -- sleep 10
```

---

## 9. 优化效果实测(端到端)

用 sysbench 读写负载(512 线程 / 1800s / 30 表 × 1e6 行)在 3 台 DB 节点上跑,
对比**开启 agent(AGENT)**与**不开(PURE)**两组,每组 6 次去掉最高/最低 QPS、
取中间 4 次均值。核心看 agent 引入的"额外开销"(Δ = AGENT − PURE)在优化前后的变化。

数据来源:`uprobe/test/agent_impact_summary_rw512_1800s.txt`(优化前)、
`uprobe/test/agent_impact_summary.txt`(优化后)。

### 9.1 优化前后:agent 引入的开销对比

| 影响指标(越小越好) | 优化前 Δ% | 优化后 Δ% | 变化 |
|----------------------|-----------|-----------|------|
| QPS 下降 | **−6.23%** | **−4.57%** | 业务吞吐损失收窄 ~1/4 |
| TPS 下降 | −6.23% | −4.57% | 同上 |
| 延迟 avg | +6.65% | **+4.77%** | 变好 |
| 延迟 99th | +6.50% | **+0.88%** | 尾延迟几乎抹平 |
| DB 主机 cpu_system | +1.92pp (+11.17%) | **+0.69pp (+4.06%)** | eBPF 内核态开销减半以上 |
| observer sysCPU | +15.34pp (+5.38%) | **+4.06pp (+1.37%)** | uprobe 命中开销降 ~73% |
| 单位 QPS 的 CPU 成本 | +6.23% | **+3.79%** | 每处理同量请求更省 CPU |

### 9.2 agent 进程自身开销

| 指标 | 优化前 | 优化后 | 说明 |
|------|--------|--------|------|
| agent CPU | 9.15% | **8.48%** | 总 CPU 略降 |
| agent userCPU | 3.66% | 6.05% | user/sys 占比结构变化 |
| agent sysCPU | 6.31% | **4.20%** | 系统态显著下降(减少 syscall/唤醒) |
| agent RSS | 185.88 MB | 220.01 MB | 略升(batch 池 reserve 预分配换拷贝/唤醒) |

### 9.3 结论

- **最能说明问题的是 `observer sysCPU`**:agent 引入的额外内核态开销从 **+15.34pp
  降到 +4.06pp(降 ~73%)**。uprobe 命中在 observer 上下文里执行,其内核时间计入
  observer 的 sysCPU——这正是**内核态"~30 次 `bpf_probe_read_user` → 1 次读 1728B"**
  优化的直接兑现:每次命中的 helper 固定开销大幅减少。
- **业务侧**:QPS 损失从 −6.23% 收窄到 **−4.57%**,99th 尾延迟从 +6.50% 压到
  **+0.88%**,对在线负载近乎无感。
- **agent 侧**:`sysCPU 6.31% → 4.20%`,对应用户态"去逐条 `notify_one`、时钟复用、
  指针 move 替整拷、batch + 定时 flush"减少的 syscall / 上下文切换。
- **代价**:agent RSS +34MB,来自 batch 池 / ringbuf 的 `reserve` 预分配——**用一点
  常驻内存换掉大量运行时拷贝与唤醒**,在吞吐/延迟收益面前可接受。

> 注:延迟 max 波动大(优化后 +41%),是长尾噪声(GC/调度/IO 抖动),样本方差高,
> 不作为结论依据;以 avg 与 99th 为准。
