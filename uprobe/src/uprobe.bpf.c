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
#define AUDIT_FRAGMENT_SAFE_PAYLOAD_4096 4095
#define AUDIT_FORCE_AND(value, mask) asm volatile("%0 &= " #mask : "+r"(value))

static __always_inline void *reserve_audit_record(unsigned int total_size)
{
	if (total_size <= AUDIT_RINGBUF_BUCKET_MAIN)
		return bpf_ringbuf_reserve(&rb, AUDIT_RINGBUF_BUCKET_MAIN, 0);
	return 0;
}

static __always_inline unsigned int fragment_payload_size(unsigned int remaining)
{
	if (remaining > AUDIT_FRAGMENT_SAFE_PAYLOAD_4096)
		return AUDIT_FRAGMENT_SAFE_PAYLOAD_4096;
	return remaining;
}

static __always_inline int read_i64(const void *base, unsigned long off, long long *dst)
{
	return bpf_probe_read_user(dst, sizeof(*dst), (const char *)base + off);
}

static __always_inline int read_u64(const void *base, unsigned long off, unsigned long long *dst)
{
	return bpf_probe_read_user(dst, sizeof(*dst), (const char *)base + off);
}

static __always_inline int read_i32(const void *base, unsigned long off, int *dst)
{
	return bpf_probe_read_user(dst, sizeof(*dst), (const char *)base + off);
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

static __always_inline unsigned int read_user_string_len(const void *base, unsigned long ptr_off,
							 unsigned long len_off, unsigned int max_len)
{
	const char *ptr = NULL;
	long long len = 0;

	if (bpf_probe_read_user(&ptr, sizeof(ptr), (const char *)base + ptr_off))
		return 0;
	if (bpf_probe_read_user(&len, sizeof(len), (const char *)base + len_off))
		return 0;
	if (!ptr || len <= 0)
		return 0;
	return clamp_len(len, max_len);
}

static __always_inline unsigned int read_user_string_payload(const void *base, unsigned long ptr_off,
							     unsigned long len_off, unsigned int max_len,
							     char *dst)
{
	const char *ptr = NULL;
	long long len = 0;
	unsigned int n;

	if (bpf_probe_read_user(&ptr, sizeof(ptr), (const char *)base + ptr_off))
		return 0;
	if (bpf_probe_read_user(&len, sizeof(len), (const char *)base + len_off))
		return 0;
	if (!ptr || len <= 0)
		return 0;
	n = clamp_len(len, max_len);
	if (n == 0 || n > max_len)
		return 0;
	bpf_probe_read_user(dst, n, ptr);
	return n;
}

static __always_inline unsigned int read_user_payload(const char *ptr, long long len,
						      unsigned int max_len, char *dst)
{
	unsigned int n;

	if (!ptr || len <= 0)
		return 0;
	n = clamp_len(len, max_len);
	if (n == 0 || n > max_len)
		return 0;
	bpf_probe_read_user(dst, n, ptr);
	return n;
}

static __always_inline u64 next_event_seq(void)
{
	u32 key = 0;
	u64 *seq_value = bpf_map_lookup_elem(&seq, &key);

	if (seq_value)
		return __sync_fetch_and_add(seq_value, 1) + 1;
	return 0;
}

/* 顺序输出 fragment：fragment i 输出后才推进到 i+1。
 * next_fragment_seq 预先按剩余字节数计算：
 *   - 当前片是最后一片逻辑片 → next = final_next_fragment_seq（跨字段链或 0）
 *   - 还有后续片 → next = next_event_seq()
 * reserve 失败则停止，已输出片链由用户态按 next_fragment_seq==0 判定尾片。 */
static __always_inline void emit_field_fragments(const char *src, long long source_len, unsigned int field,
							 unsigned int first_offset, u64 parent_event_seq,
							 u64 first_fragment_seq, u64 final_next_fragment_seq)
{
	unsigned int capture_len;
	unsigned int offset = first_offset;
	u64 fragment_seq = first_fragment_seq;
	int i;

	if (!src)
		return;
	capture_len = clamp_len(source_len, field == FRAG_FIELD_QUERY_SQL ? AUDIT_SQL_CAPTURE_MAX : AUDIT_PARAMS_CAPTURE_MAX);

#pragma unroll
	for (i = 0; i < AUDIT_MAX_FRAGMENTS_PER_FIELD; i++) {
		struct audit_fragment_record *s;
		unsigned int remaining;
		unsigned int copied;
		unsigned int out_size;
		u64 next_seq;
		bool is_last;

		if (offset >= capture_len || fragment_seq == 0)
			break;
		remaining = capture_len - offset;
		copied = fragment_payload_size(remaining);
		AUDIT_FORCE_AND(copied, 4095);
		if (copied == 0)
			break;
		is_last = (remaining <= copied);
		if (is_last) {
			next_seq = final_next_fragment_seq;
		} else {
			next_seq = next_event_seq();
			if (next_seq == 0)
				next_seq = final_next_fragment_seq;
		}

		s = bpf_ringbuf_reserve(&rb, AUDIT_FRAGMENT_BUCKET, 0);
		if (!s)
			break;
		out_size = AUDIT_FRAGMENT_HEADER_SIZE + copied;
		s->total_size = out_size;
		s->record_type = AUDIT_RECORD_FRAGMENT;
		s->record_flags = AUDIT_RECORD_FLAG_FRAGMENT;
		if (next_seq == 0)
			s->record_flags |= AUDIT_RECORD_FLAG_LAST_FRAGMENT | AUDIT_RECORD_FLAG_LOGICAL_COMPLETE;
		s->event_seq = fragment_seq;
		s->parent_event_seq = parent_event_seq;
		s->next_fragment_seq = next_seq;
		s->field = field;
		s->fragment_offset = offset;
		s->payload_len = copied;
		bpf_probe_read_user(s->payload, copied, src + offset);
		bpf_ringbuf_submit(s, 0);

		if (is_last)
			break;
		offset += copied;
		fragment_seq = next_seq;
	}
}

static __always_inline void read_addr_field(const void *base, unsigned long addr_off, char *dst, int dst_size)
{
	if (dst_size < OB_ADDR_SIZE)
		return;
	bpf_probe_read_user(dst, OB_ADDR_SIZE, (const char *)base + addr_off);
}

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx)
{
	struct event *e;
	const void *audit_record;
	const char *sql = NULL;
	const char *params_value = NULL;
	long long sql_len = 0;
	long long params_value_len = 0;
	long long receive_ts = 0;
	long long process_executor_ts = 0;
	long long executor_end_ts = 0;
	long long multistmt_start_ts = 0;
	long long elapsed_t = 0;
	long long executor_t = 0;
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
	unsigned int user_name_len = 0;
	unsigned int proxy_user_name_len = 0;
	unsigned int tenant_name_len = 0;
	unsigned int db_name_len = 0;
	unsigned int planned_payload_len = 0;
	unsigned int main_out_size = 0;
#if AUDIT_PERF_FIELDS_ENABLED
		u64 perf_bpf_entry_ns = bpf_ktime_get_ns();
#endif

		// RSI传参，第二参数是目标参数，c++第一个参数隐式this指针
	audit_record = (const void *)PT_REGS_PARM2(ctx);
	if (!audit_record)
		return 0;

	read_bool(audit_record, OB_AUDIT_IS_INNER_SQL_OFF, &is_inner_sql);
	if (is_inner_sql)
		return 0;

	// 读取审计记录中的SQL语句和长度
	if (bpf_probe_read_user(&sql, sizeof(sql), (const char *)audit_record + OB_AUDIT_SQL_PTR_OFF))
		return 0;
	if (bpf_probe_read_user(&sql_len, sizeof(sql_len), (const char *)audit_record + OB_AUDIT_SQL_LEN_OFF))
		return 0;
	if (!sql || sql_len <= 0)
		return 0;

	if (!bpf_probe_read_user(&params_value, sizeof(params_value), (const char *)audit_record + OB_AUDIT_PARAMS_VALUE_PTR_OFF))
		bpf_probe_read_user(&params_value_len, sizeof(params_value_len), (const char *)audit_record + OB_AUDIT_PARAMS_VALUE_LEN_OFF);
	if (!params_value || params_value_len <= 0)
		params_value_len = 0;

	user_name_len = read_user_string_len(audit_record, OB_AUDIT_USER_NAME_PTR_OFF, OB_AUDIT_USER_NAME_LEN_OFF, MAX_NAME_LEN - 1);
	proxy_user_name_len = read_user_string_len(audit_record, OB_AUDIT_PROXY_USER_NAME_PTR_OFF, OB_AUDIT_PROXY_USER_NAME_LEN_OFF, MAX_NAME_LEN - 1);
	tenant_name_len = read_user_string_len(audit_record, OB_AUDIT_TENANT_NAME_PTR_OFF, OB_AUDIT_TENANT_NAME_LEN_OFF, MAX_NAME_LEN - 1);
	db_name_len = read_user_string_len(audit_record, OB_AUDIT_DB_NAME_PTR_OFF, OB_AUDIT_DB_NAME_LEN_OFF, MAX_DB_NAME_LEN - 1);
	sql_first_len = clamp_len(sql_len, AUDIT_MAIN_SQL_PAYLOAD_MAX);
	params_first_len = clamp_len(params_value_len, AUDIT_MAIN_PARAMS_PAYLOAD_MAX);

	planned_payload_len = user_name_len + proxy_user_name_len + tenant_name_len + db_name_len + sql_first_len + params_first_len;
	main_out_size = event_payload_offset() + planned_payload_len;
	if (main_out_size > sizeof(*e) || main_out_size > AUDIT_RINGBUF_MAX_BUCKET)
		return 0;
	count_ob_audit_seen();
	e = reserve_audit_record(main_out_size);
	if (!e) {
		count_ringbuf_full_drop();
		return 0;
	}

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

	read_i32(audit_record, OB_AUDIT_STATUS_OFF, &e->ret_code);
	bpf_probe_read_user(&e->trace_id, sizeof(e->trace_id), (const char *)audit_record + OB_AUDIT_TRACE_ID_OFF);
	read_u64(audit_record, OB_AUDIT_REQUEST_ID_OFF, &e->request_id);
	read_u64(audit_record, OB_AUDIT_SESSION_ID_OFF, &e->session_id);
	read_u64(audit_record, OB_AUDIT_PROXY_SESSION_ID_OFF, &e->proxy_session_id);
	read_u64(audit_record, OB_AUDIT_TENANT_ID_OFF, &e->tenant_id);
	read_u64(audit_record, OB_AUDIT_EFFECTIVE_TENANT_ID_OFF, &e->effective_tenant_id);
	read_u64(audit_record, OB_AUDIT_USER_ID_OFF, &e->user_id);
	read_u64(audit_record, OB_AUDIT_DB_ID_OFF, &e->db_id);
	read_u64(audit_record, OB_AUDIT_AFFECTED_ROWS_OFF, &e->affected_rows);
	read_u64(audit_record, OB_AUDIT_RETURN_ROWS_OFF, &e->return_rows);
	read_u64(audit_record, OB_AUDIT_TRANS_ID_OFF, &e->transaction_hash);
	read_i32(audit_record, OB_AUDIT_PLAN_TYPE_OFF, (int *)&e->plan_type);
	read_i32(audit_record, OB_AUDIT_STMT_TYPE_OFF, &e->stmt_type);
	read_i32(audit_record, OB_AUDIT_TRANS_STATUS_OFF, (int *)&e->trans_status);
	bpf_probe_read_user(e->sql_id, sizeof(e->sql_id), (const char *)audit_record + OB_AUDIT_SQL_ID_OFF);

	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_RECEIVE_TS_OFF, &receive_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_PROCESS_EXECUTOR_TS_OFF, &process_executor_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_EXECUTOR_END_TS_OFF, &executor_end_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_MULTI_STMT_START_TS_OFF, &multistmt_start_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_ELAPSED_T_OFF, &elapsed_t);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_EXECUTOR_T_OFF, &executor_t);
	e->request_timestamp = receive_ts;
	e->elapsed_time = elapsed_t;
	e->execute_time = executor_t;
	if (e->elapsed_time <= 0 && executor_end_ts > 0) {
		if (multistmt_start_ts > 0)
			e->elapsed_time = executor_end_ts - multistmt_start_ts;
		else if (receive_ts > 0)
			e->elapsed_time = executor_end_ts - receive_ts;
	}
	if (e->execute_time <= 0 && executor_end_ts > 0 && process_executor_ts > 0)
		e->execute_time = executor_end_ts - process_executor_ts;

	read_addr_field(audit_record, OB_AUDIT_USER_CLIENT_ADDR_OFF,
			e->user_client_ip, sizeof(e->user_client_ip));
	read_addr_field(audit_record, OB_AUDIT_CLIENT_ADDR_OFF,
			e->client_ip, sizeof(e->client_ip));
	__builtin_memset(e->server_ip, 0, sizeof(e->server_ip));

	payload = e->payload;
	copied = read_user_string_payload(audit_record, OB_AUDIT_USER_NAME_PTR_OFF, OB_AUDIT_USER_NAME_LEN_OFF, MAX_NAME_LEN - 1, payload);
	e->user_name_len = copied;
	payload += copied;
	payload_len += copied;
	copied = read_user_string_payload(audit_record, OB_AUDIT_PROXY_USER_NAME_PTR_OFF,
					  OB_AUDIT_PROXY_USER_NAME_LEN_OFF, MAX_NAME_LEN - 1, payload);
	e->proxy_user_name_len = copied;
	payload += copied;
	payload_len += copied;
	copied = read_user_string_payload(audit_record, OB_AUDIT_TENANT_NAME_PTR_OFF,
					  OB_AUDIT_TENANT_NAME_LEN_OFF, MAX_NAME_LEN - 1, payload);
	e->tenant_name_len = copied;
	payload += copied;
	payload_len += copied;
	copied = read_user_string_payload(audit_record, OB_AUDIT_DB_NAME_PTR_OFF, OB_AUDIT_DB_NAME_LEN_OFF, MAX_DB_NAME_LEN - 1, payload);
	e->db_name_len = copied;
	payload += copied;
	payload_len += copied;
	copied = read_user_payload(sql, sql_len, AUDIT_MAIN_SQL_PAYLOAD_MAX, payload);
	e->query_sql_payload_len = copied;
	payload += copied;
	payload_len += copied;
	copied = read_user_payload(params_value, params_value_len, AUDIT_MAIN_PARAMS_PAYLOAD_MAX, payload);
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
		if (out_size > main_out_size)
			out_size = main_out_size;
		e->total_size = out_size;
#if AUDIT_PERF_FIELDS_ENABLED
		e->perf_bpf_before_output_ns = bpf_ktime_get_ns();
#endif
		bpf_ringbuf_submit(e, 0);
	}
	if (main_fragment_flags & FRAG_QUERY_SQL_FRAGMENTED)
		emit_field_fragments(sql, sql_len, FRAG_FIELD_QUERY_SQL, sql_first_len, main_event_seq,
					     first_fragment_seq, params_first_fragment_seq);
	if (main_fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED)
		emit_field_fragments(params_value, params_value_len, FRAG_FIELD_PARAMS_VALUE, params_first_len, main_event_seq,
					     params_first_fragment_seq, 0);
	return 0;
}
