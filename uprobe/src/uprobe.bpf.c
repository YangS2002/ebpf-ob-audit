// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

#define OB_AUDIT_STATUS_OFF 4
#define OB_AUDIT_TRACE_ID_OFF 8
#define OB_AUDIT_REQUEST_ID_OFF 40
#define OB_AUDIT_SESSION_ID_OFF 56
#define OB_AUDIT_PROXY_SESSION_ID_OFF 64
#define OB_AUDIT_TENANT_ID_OFF 176
#define OB_AUDIT_EFFECTIVE_TENANT_ID_OFF 184
#define OB_AUDIT_TENANT_NAME_PTR_OFF 192
#define OB_AUDIT_TENANT_NAME_LEN_OFF 200
#define OB_AUDIT_USER_ID_OFF 208
#define OB_AUDIT_USER_NAME_PTR_OFF 216
#define OB_AUDIT_USER_NAME_LEN_OFF 224
#define OB_AUDIT_PROXY_USER_NAME_PTR_OFF 240
#define OB_AUDIT_PROXY_USER_NAME_LEN_OFF 248
#define OB_AUDIT_DB_ID_OFF 264
#define OB_AUDIT_DB_NAME_PTR_OFF 272
#define OB_AUDIT_DB_NAME_LEN_OFF 280
#define OB_AUDIT_SQL_ID_OFF 288
#define OB_AUDIT_SQL_PTR_OFF 328
#define OB_AUDIT_SQL_LEN_OFF 336
#define OB_AUDIT_AFFECTED_ROWS_OFF 360
#define OB_AUDIT_RETURN_ROWS_OFF 368
#define OB_AUDIT_PLAN_TYPE_OFF 408
#define OB_AUDIT_EXEC_TIMESTAMP_OFF 432
#define OB_AUDIT_TRANS_ID_OFF 1320
#define OB_AUDIT_PARAMS_VALUE_LEN_OFF 1352
#define OB_AUDIT_PARAMS_VALUE_PTR_OFF 1360
#define OB_AUDIT_STMT_TYPE_OFF 1684
#define OB_AUDIT_TRANS_STATUS_OFF 1720

#define OB_EXEC_RECEIVE_TS_OFF 0
#define OB_EXEC_PROCESS_TS_OFF 8
#define OB_EXEC_EXECUTOR_END_TS_OFF 88
#define OB_EXEC_MULTI_STMT_START_TS_OFF 128

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 
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
	__type(value, struct event);
} zero_event SEC(".maps");

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

static __always_inline void read_user_string_field(const void *base, unsigned long ptr_off, unsigned long len_off,
						  char *dst, int dst_size)
{
	const char *ptr = NULL;
	long long len = 0;

	if (bpf_probe_read_user(&ptr, sizeof(ptr), (const char *)base + ptr_off))
		return;
	if (bpf_probe_read_user(&len, sizeof(len), (const char *)base + len_off))
		return;
	if (!ptr || len <= 0)
		return;
	bpf_probe_read_user_str(dst, dst_size, ptr);
}

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx)
{
	struct event *e;
	struct event *zero;
	const void *audit_record;
	const char *sql = NULL;
	const char *params_value = NULL;
	long long sql_len = 0;
	long long params_value_len = 0;
	long long receive_ts = 0;
	long long process_ts = 0;
	long long executor_end_ts = 0;
	long long multistmt_start_ts = 0;
	u32 key = 0;
	u64 *seq_value;
	u64 id;

	// RSI传参，第二参数是目标参数，c++第一个参数隐式this指针
	audit_record = (const void *)PT_REGS_PARM2(ctx);
	if (!audit_record)
		return 0;

	// 读取审计记录中的SQL语句和长度
	if (bpf_probe_read_user(&sql, sizeof(sql), (const char *)audit_record + OB_AUDIT_SQL_PTR_OFF))
		return 0;
	if (bpf_probe_read_user(&sql_len, sizeof(sql_len), (const char *)audit_record + OB_AUDIT_SQL_LEN_OFF))
		return 0;
	if (!sql || sql_len <= 0)
		return 0;

	// 缓冲区预留，!e表示缓冲区满，当前审计记录会丢失
	// 检查是否还有一个entry的空间，一个entry就是一个event结构体的大小
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	id = bpf_get_current_pid_tgid();
	zero = bpf_map_lookup_elem(&zero_event, &key);
	if (zero)
		bpf_probe_read_kernel(e, sizeof(*e), zero); // 将e的内存空间置0，内核态不能调用memset
	e->pid = id >> 32;
	e->tid = (u32)id;
	seq_value = bpf_map_lookup_elem(&seq, &key);
	if (seq_value)
		e->event_seq = __sync_fetch_and_add(seq_value, 1) + 1;
	// sql 分帧，暂时没做完
	e->query_sql_len = sql_len;
	e->fragment_flags = 0;
	e->next_fragment_field = FRAG_FIELD_NONE;
	if (sql_len >= MAX_SQL_LEN) {
		e->fragment_flags |= FRAG_QUERY_SQL_TRUNCATED;
		e->next_fragment_field = FRAG_FIELD_QUERY_SQL;
	}
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	if (bpf_probe_read_user_str(e->query_sql, sizeof(e->query_sql), sql) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	if (!bpf_probe_read_user(&params_value, sizeof(params_value), (const char *)audit_record + OB_AUDIT_PARAMS_VALUE_PTR_OFF) &&
	    !bpf_probe_read_user(&params_value_len, sizeof(params_value_len), (const char *)audit_record + OB_AUDIT_PARAMS_VALUE_LEN_OFF)) {
		e->params_value_len = params_value_len;
		if (params_value && params_value_len > 0) {
			if (params_value_len >= MAX_PARAMS_VALUE_LEN) {
				e->fragment_flags |= FRAG_PARAMS_VALUE_TRUNCATED;
				if (e->next_fragment_field == FRAG_FIELD_NONE)
					e->next_fragment_field = FRAG_FIELD_PARAMS_VALUE;
			}
			bpf_probe_read_user_str(e->params_value, sizeof(e->params_value), params_value);
		}
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
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_PROCESS_TS_OFF, &process_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_EXECUTOR_END_TS_OFF, &executor_end_ts);
	read_i64(audit_record, OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_MULTI_STMT_START_TS_OFF, &multistmt_start_ts);
	e->request_timestamp = receive_ts;
	if (executor_end_ts > 0) {
		if (multistmt_start_ts > 0)
			e->elapsed_time = executor_end_ts - multistmt_start_ts;
		else if (receive_ts > 0)
			e->elapsed_time = executor_end_ts - receive_ts;
		if (process_ts > 0)
			e->execute_time = executor_end_ts - process_ts;
	}

	read_user_string_field(audit_record, OB_AUDIT_TENANT_NAME_PTR_OFF, OB_AUDIT_TENANT_NAME_LEN_OFF,
			       e->tenant_name, sizeof(e->tenant_name));
	read_user_string_field(audit_record, OB_AUDIT_USER_NAME_PTR_OFF, OB_AUDIT_USER_NAME_LEN_OFF,
			       e->user_name, sizeof(e->user_name));
	read_user_string_field(audit_record, OB_AUDIT_PROXY_USER_NAME_PTR_OFF, OB_AUDIT_PROXY_USER_NAME_LEN_OFF,
			       e->proxy_user_name, sizeof(e->proxy_user_name));
	read_user_string_field(audit_record, OB_AUDIT_DB_NAME_PTR_OFF, OB_AUDIT_DB_NAME_LEN_OFF,
			       e->db_name, sizeof(e->db_name));

	// 提交缓冲区
	bpf_ringbuf_submit(e, 0);
	return 0;
}
