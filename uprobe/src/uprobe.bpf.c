// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"
#include "audit_loss_metrics.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, AUDIT_RINGBUF_SIZE);
} rb SEC(".maps");

// 序列号，bpf无法定义全局变量，只能通过map来实现全局变量
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} seq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct audit_bpf_loss_stats);
} loss_stats SEC(".maps");

static __always_inline void count_ob_audit_seen(void)
{
	u32 key = 0;
	struct audit_bpf_loss_stats *stats = bpf_map_lookup_elem(&loss_stats, &key);

	if (stats)
		__sync_fetch_and_add(&stats->ob_audit_seen_records, 1);
}

static __always_inline void count_ringbuf_full_drop(void)
{
	u32 key = 0;
	struct audit_bpf_loss_stats *stats = bpf_map_lookup_elem(&loss_stats, &key);

	if (stats)
		__sync_fetch_and_add(&stats->ringbuf_full_dropped_records, 1);
}

#define AUDIT_STATIC_ASSERT(cond, name) typedef char audit_static_assert_##name[(cond) ? 1 : -1]
AUDIT_STATIC_ASSERT(AUDIT_FRAGMENT_HEADER_SIZE + AUDIT_FRAGMENT_PAYLOAD_MAX < AUDIT_FRAGMENT_BUCKET, fragment_fits_bucket);
#define AUDIT_FORCE_AND(value, mask) asm volatile("%0 &= " #mask : "+r"(value))

static __always_inline void *reserve_audit_record(unsigned int total_size)
{
	if (total_size <= AUDIT_RINGBUF_BUCKET_MAIN)
		return bpf_ringbuf_reserve(&rb, AUDIT_RINGBUF_BUCKET_MAIN, 0);
	return 0;
}

static __always_inline unsigned int fragment_payload_size(unsigned int remaining)
{
	if (remaining > AUDIT_FRAGMENT_PAYLOAD_MAX)
		return AUDIT_FRAGMENT_PAYLOAD_MAX;
	return remaining;
}

static __always_inline int read_bool(const void *base, unsigned long off, bool *dst)
{
	return bpf_probe_read_user(dst, sizeof(*dst), (const char *)base + off);
}

static __always_inline unsigned int clamp_len(long long len, unsigned int max_len)
{
	if (len <= 0)
		return 0;
	if (len > max_len)
		return max_len;
	return (unsigned int)len;
}

/* 从已 bulk 拷入的定长区 buffer 里按常量偏移取值(内核内存读，无 user 拷贝)。 */
static __always_inline unsigned long long raw_u64(const unsigned char *r, unsigned int off)
{
	unsigned long long v;
	__builtin_memcpy(&v, r + off, sizeof(v));
	return v;
}

static __always_inline long long raw_i64(const unsigned char *r, unsigned int off)
{
	long long v;
	__builtin_memcpy(&v, r + off, sizeof(v));
	return v;
}

static __always_inline u64 next_event_seq(void)
{
	u32 key = 0;
	u64 *seq_value = bpf_map_lookup_elem(&seq, &key);

	if (seq_value)
		return __sync_fetch_and_add(seq_value, 1) + 1;
	return 0;
}

/* 单 fragment 输出：每字段至多一片(<=64KB)，超出 64KB 的部分截断
 * (TRUNCATED flag 已在 main event 上置位)。
 * next_fragment_seq = final_next_fragment_seq（跨字段链或 0，0 即尾片）。
 * 目标内核 5.8：无循环无展开，消除 verifier 状态爆炸。
 * reserve 失败则放弃该片，用户态按 next_fragment_seq 断链判定丢失。 */
static __always_inline void emit_field_fragment(const char *src, long long source_len, unsigned int field,
							unsigned int first_offset, u64 parent_event_seq,
							u64 first_fragment_seq, u64 final_next_fragment_seq)
{
	struct audit_fragment_record *s;
	unsigned int capture_len;
	unsigned int remaining;
	unsigned int copied;

	if (!src || first_fragment_seq == 0)
		return;
	capture_len = clamp_len(source_len, field == FRAG_FIELD_QUERY_SQL ? AUDIT_SQL_CAPTURE_MAX : AUDIT_PARAMS_CAPTURE_MAX);
	if (first_offset >= capture_len)
		return;
	remaining = capture_len - first_offset;
	copied = fragment_payload_size(remaining);
	AUDIT_FORCE_AND(copied, 65535);
	if (copied == 0)
		return;

	s = bpf_ringbuf_reserve(&rb, AUDIT_FRAGMENT_BUCKET, 0);
	if (!s)
		return;
	s->total_size = AUDIT_FRAGMENT_HEADER_SIZE + copied;
	s->record_type = AUDIT_RECORD_FRAGMENT;
	s->record_flags = AUDIT_RECORD_FLAG_FRAGMENT;
	if (final_next_fragment_seq == 0)
		s->record_flags |= AUDIT_RECORD_FLAG_LAST_FRAGMENT | AUDIT_RECORD_FLAG_LOGICAL_COMPLETE;
	s->event_seq = first_fragment_seq;
	s->parent_event_seq = parent_event_seq;
	s->next_fragment_seq = final_next_fragment_seq;
	s->field = field;
	s->fragment_offset = first_offset;
	s->payload_len = copied;
	bpf_probe_read_user(s->payload, copied, src + first_offset);
	// NO_WAKEUP: 不在生产侧(observer 线程)触发 irq_work 唤醒消费者，
	// 由 agent 端自轮询 ring_buffer__consume 抽取。降低 observer CPU 开销。
	bpf_ringbuf_submit(s, BPF_RB_NO_WAKEUP);
}

/* 主记录(头 + ob_raw + 最大 name 段 + sql 首片 + params 首片)必须放进 main bucket。 */
AUDIT_STATIC_ASSERT(__builtin_offsetof(struct event, payload) + (MAX_NAME_LEN - 1) * 3 + (MAX_DB_NAME_LEN - 1) +
			    AUDIT_MAIN_SQL_PAYLOAD_MAX + AUDIT_MAIN_PARAMS_PAYLOAD_MAX <=
		    AUDIT_RINGBUF_BUCKET_MAIN,
		    main_record_fits_bucket);
AUDIT_STATIC_ASSERT(OB_AUDIT_RAW_FIXED_SIZE >= OB_AUDIT_TRANS_STATUS_OFF + 4, raw_covers_all_offsets);

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx)
{
	struct event *e;
	const void *audit_record;
	const unsigned char *r;
	const char *sql = NULL;
	const char *params_value = NULL;
	const char *user_ptr = NULL;
	const char *proxy_ptr = NULL;
	const char *tenant_ptr = NULL;
	const char *db_ptr = NULL;
	long long sql_len = 0;
	long long params_value_len = 0;
	long long user_len = 0;
	long long proxy_len = 0;
	long long tenant_len = 0;
	long long db_len = 0;
	bool is_inner_sql = false;
	u64 id;
	char *payload;
	unsigned int payload_len = 0;
	unsigned int copied = 0;
	u64 first_fragment_seq = 0;
	u64 params_first_fragment_seq = 0;
	u64 main_event_seq = 0;
	unsigned int main_fragment_flags = 0;
	unsigned int sql_first_len = 0;
	unsigned int params_first_len = 0;
#if AUDIT_PERF_FIELDS_ENABLED
		u64 perf_bpf_entry_ns = bpf_ktime_get_ns();
#endif

		// RSI传参，第二参数是目标参数，c++第一个参数隐式this指针
	audit_record = (const void *)PT_REGS_PARM2(ctx);
	if (!audit_record)
		return 0;

	// 唯一在 bulk 读之前的 user 读：1 字节 is_inner，尽早过滤内部 SQL，
	// 避免对被丢弃的内部 SQL 白拷 1728 字节。
	read_bool(audit_record, OB_AUDIT_IS_INNER_SQL_OFF, &is_inner_sql);
	if (is_inner_sql)
		return 0;

	// 先 reserve 定长 bucket，再把连续定长区 [0,1728) 一次性 bulk 读入 ob_raw。
	// 标量/ptr-len 不再逐字段读，全部从 ob_raw 内核副本里取(免费)，collector 端解析。
	e = reserve_audit_record(AUDIT_RINGBUF_BUCKET_MAIN);
	if (!e) {
		count_ob_audit_seen();
		count_ringbuf_full_drop();
		return 0;
	}
	if (bpf_probe_read_user(e->ob_raw, OB_AUDIT_RAW_FIXED_SIZE, audit_record)) {
		bpf_ringbuf_discard(e, BPF_RB_NO_WAKEUP);
		return 0;
	}
	r = e->ob_raw;

	// sql: [ptr@328][len@336]
	sql = (const char *)raw_u64(r, OB_AUDIT_SQL_PTR_OFF);
	sql_len = raw_i64(r, OB_AUDIT_SQL_LEN_OFF);
	if (!sql || sql_len <= 0) {
		bpf_ringbuf_discard(e, BPF_RB_NO_WAKEUP);
		return 0;
	}
	count_ob_audit_seen();

	// params: [len@1352][ptr@1360]
	params_value = (const char *)raw_u64(r, OB_AUDIT_PARAMS_VALUE_PTR_OFF);
	params_value_len = raw_i64(r, OB_AUDIT_PARAMS_VALUE_LEN_OFF);
	if (!params_value || params_value_len <= 0)
		params_value_len = 0;

	// 4 个 name 的 ptr/len 均取自 ob_raw；ptr 非法则置长度 0。
	user_ptr = (const char *)raw_u64(r, OB_AUDIT_USER_NAME_PTR_OFF);
	user_len = raw_i64(r, OB_AUDIT_USER_NAME_LEN_OFF);
	if (!user_ptr || user_len <= 0)
		user_len = 0;
	proxy_ptr = (const char *)raw_u64(r, OB_AUDIT_PROXY_USER_NAME_PTR_OFF);
	proxy_len = raw_i64(r, OB_AUDIT_PROXY_USER_NAME_LEN_OFF);
	if (!proxy_ptr || proxy_len <= 0)
		proxy_len = 0;
	tenant_ptr = (const char *)raw_u64(r, OB_AUDIT_TENANT_NAME_PTR_OFF);
	tenant_len = raw_i64(r, OB_AUDIT_TENANT_NAME_LEN_OFF);
	if (!tenant_ptr || tenant_len <= 0)
		tenant_len = 0;
	db_ptr = (const char *)raw_u64(r, OB_AUDIT_DB_NAME_PTR_OFF);
	db_len = raw_i64(r, OB_AUDIT_DB_NAME_LEN_OFF);
	if (!db_ptr || db_len <= 0)
		db_len = 0;

	main_event_seq = next_event_seq();
	id = bpf_get_current_pid_tgid();
	e->record_type = AUDIT_RECORD_EVENT;
	e->record_flags = 0;
	e->event_seq = main_event_seq;
	e->parent_event_seq = 0;
	e->next_fragment_seq = 0;
	e->pid = id >> 32;
	e->tid = (u32)id;

	e->query_sql_len = sql_len;
	e->params_value_len = 0;
#if AUDIT_PERF_FIELDS_ENABLED
		e->perf_bpf_entry_ns = perf_bpf_entry_ns;
		e->perf_bpf_before_output_ns = 0;
		e->perf_agent_receive_ns = 0;
		e->perf_agent_before_submit_ns = 0;
		e->perf_agent_after_submit_ns = 0;
		e->perf_collector_receive_ns = 0;
		e->perf_mongo_before_insert_ns = 0;
#endif
	e->fragment_flags = 0;
	e->next_fragment_field = FRAG_FIELD_NONE;
	if (sql_len > AUDIT_MAIN_SQL_PAYLOAD_MAX) {
		e->fragment_flags |= FRAG_QUERY_SQL_FRAGMENTED;
		e->next_fragment_field = FRAG_FIELD_QUERY_SQL;
	}
	if (sql_len > AUDIT_SQL_CAPTURE_MAX)
		e->fragment_flags |= FRAG_QUERY_SQL_TRUNCATED;
	if (params_value && params_value_len > 0) {
		e->params_value_len = params_value_len;
		if (params_value_len > AUDIT_MAIN_PARAMS_PAYLOAD_MAX) {
			e->fragment_flags |= FRAG_PARAMS_VALUE_FRAGMENTED;
			if (e->next_fragment_field == FRAG_FIELD_NONE)
				e->next_fragment_field = FRAG_FIELD_PARAMS_VALUE;
		}
		if (params_value_len > AUDIT_PARAMS_CAPTURE_MAX)
			e->fragment_flags |= FRAG_PARAMS_VALUE_TRUNCATED;
	}
	// 标量(status/ids/时间戳/addr/trace_id/sql_id/...) 不在 BPF 端解析，
	// 由 collector 从 ob_raw 按 OB_*_OFF 抽取(event_fill_scalars_from_ob_raw)。

	payload = e->payload;
	// 拷贝：ptr/len 取自 ob_raw；AUDIT_FORCE_AND 用字面量给 verifier 常量上界。
	// 不加 if (copied) 分支：probe_read_user size 为 ARG_CONST_SIZE_OR_ZERO，
	// copied==0 是合法空写（src 为 NULL 时仅返回 -EFAULT）。6 个 if 会产生
	// 2^6=64 条 payload_len 不同的路径变体，导致 verifier 状态爆炸。
	copied = clamp_len(user_len, MAX_NAME_LEN - 1);
	AUDIT_FORCE_AND(copied, 63);
	bpf_probe_read_user(payload, copied, user_ptr);
	e->user_name_len = copied;
	payload_len += copied;
	AUDIT_FORCE_AND(payload_len, 2047);
	payload = e->payload + payload_len;
	copied = clamp_len(proxy_len, MAX_NAME_LEN - 1);
	AUDIT_FORCE_AND(copied, 63);
	bpf_probe_read_user(payload, copied, proxy_ptr);
	e->proxy_user_name_len = copied;
	payload_len += copied;
	AUDIT_FORCE_AND(payload_len, 2047);
	payload = e->payload + payload_len;
	copied = clamp_len(tenant_len, MAX_NAME_LEN - 1);
	AUDIT_FORCE_AND(copied, 63);
	bpf_probe_read_user(payload, copied, tenant_ptr);
	e->tenant_name_len = copied;
	payload_len += copied;
	AUDIT_FORCE_AND(payload_len, 2047);
	payload = e->payload + payload_len;
	copied = clamp_len(db_len, MAX_DB_NAME_LEN - 1);
	AUDIT_FORCE_AND(copied, 127);
	bpf_probe_read_user(payload, copied, db_ptr);
	e->db_name_len = copied;
	payload_len += copied;
	AUDIT_FORCE_AND(payload_len, 2047);
	payload = e->payload + payload_len;
	copied = clamp_len(sql_len, AUDIT_MAIN_SQL_PAYLOAD_MAX);
	AUDIT_FORCE_AND(copied, 1023);
	bpf_probe_read_user(payload, copied, sql);
	e->query_sql_payload_len = copied;
	payload_len += copied;
	AUDIT_FORCE_AND(payload_len, 2047);
	payload = e->payload + payload_len;
	copied = clamp_len(params_value_len, AUDIT_MAIN_PARAMS_PAYLOAD_MAX);
	AUDIT_FORCE_AND(copied, 255);
	bpf_probe_read_user(payload, copied, params_value);
	e->params_value_payload_len = copied;
	payload_len += copied;
	e->record_flags = AUDIT_RECORD_FLAG_PHYSICAL_COMPLETE;
	if (e->fragment_flags & (FRAG_QUERY_SQL_TRUNCATED | FRAG_PARAMS_VALUE_TRUNCATED))
		e->record_flags = 0;
	if ((e->fragment_flags & (FRAG_QUERY_SQL_FRAGMENTED | FRAG_PARAMS_VALUE_FRAGMENTED)) == 0)
		e->record_flags |= AUDIT_RECORD_FLAG_LOGICAL_COMPLETE;
	main_fragment_flags = e->fragment_flags;
	sql_first_len = e->query_sql_payload_len;
	params_first_len = e->params_value_payload_len;
	if (main_fragment_flags & FRAG_QUERY_SQL_FRAGMENTED) {
		first_fragment_seq = next_event_seq();
		if (main_fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED)
			params_first_fragment_seq = next_event_seq();
	} else if (main_fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED) {
		first_fragment_seq = next_event_seq();
		params_first_fragment_seq = first_fragment_seq;
	}
	e->next_fragment_seq = first_fragment_seq;
	{
		unsigned int out_size = event_payload_offset() + payload_len;
		if (out_size > AUDIT_RINGBUF_BUCKET_MAIN)
			out_size = AUDIT_RINGBUF_BUCKET_MAIN;
		e->total_size = out_size;
#if AUDIT_PERF_FIELDS_ENABLED
		e->perf_bpf_before_output_ns = bpf_ktime_get_ns();
#endif
		// NO_WAKEUP: 见 emit_field_fragment 处说明。生产侧不唤醒消费者，
		// agent 端改为自轮询 consume（uprobe.cpp）。两处 submit flag 必须一致。
		bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
	}
	if (main_fragment_flags & FRAG_QUERY_SQL_FRAGMENTED)
		emit_field_fragment(sql, sql_len, FRAG_FIELD_QUERY_SQL, sql_first_len, main_event_seq,
				    first_fragment_seq, params_first_fragment_seq);
	if (main_fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED)
		emit_field_fragment(params_value, params_value_len, FRAG_FIELD_PARAMS_VALUE, params_first_len, main_event_seq,
				    params_first_fragment_seq, 0);
	return 0;
}
