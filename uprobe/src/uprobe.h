/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UPROBE_H
#define __UPROBE_H

#include "audit_record.h"

#ifndef AUDIT_PERF_FIELDS_ENABLED
#define AUDIT_PERF_FIELDS_ENABLED 0
#endif

/* v7/v8: raw-record offload. BPF bulk-copies the contiguous OB audit-record
 * fixed region into event.ob_raw and stops parsing scalars in-kernel; the
 * collector extracts scalar fields from ob_raw by OB_AUDIT_*_OFF offset. */
#if AUDIT_PERF_FIELDS_ENABLED
#define AUDIT_FILE_VERSION_VALUE 8
#else
#define AUDIT_FILE_VERSION_VALUE 7
#endif

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN 64
#define MAX_IP_LEN OB_ADDR_SIZE
#define MAX_DB_NAME_LEN 128
#define MAX_SQL_ID_LEN 33 // 32 + 1
#define MAX_TRACE_ID_LEN 128
#define MAX_SQL_LEN AUDIT_SQL_CAPTURE_MAX
#define MAX_PARAMS_VALUE_LEN AUDIT_PARAMS_CAPTURE_MAX

/* BPF 端 struct event 的 payload 上限。
 * 用户态需要容纳完整 SQL+params（含分片合并结果），用 AUDIT_EVENT_PAYLOAD_SIZE。
 * BPF 端只发 main event 的 first chunks，payload 最大 =
 *   三个 name + db_name + sql first + params first
 * 缩小后 struct event 才能放进 per-cpu array（受 per-cpu 区域大小限制，约 32KB）。 */
#ifdef __BPF__
#undef AUDIT_EVENT_PAYLOAD_SIZE
#define AUDIT_EVENT_PAYLOAD_SIZE \
	(MAX_NAME_LEN + MAX_NAME_LEN + MAX_NAME_LEN + \
	 MAX_DB_NAME_LEN + AUDIT_MAIN_SQL_PAYLOAD_MAX + AUDIT_MAIN_PARAMS_PAYLOAD_MAX)
#endif

#define OB_AUDIT_STATUS_OFF 4
#define OB_AUDIT_TRACE_ID_OFF 8
#define OB_AUDIT_REQUEST_ID_OFF 40
#define OB_AUDIT_EXECUTION_ID_OFF 48
#define OB_AUDIT_SESSION_ID_OFF 56
#define OB_AUDIT_PROXY_SESSION_ID_OFF 64
#define OB_AUDIT_WORKER_ID_OFF 96
#define OB_AUDIT_SERVER_ADDR_OFF 104
#define OB_AUDIT_CLIENT_ADDR_OFF 128
#define OB_AUDIT_USER_CLIENT_ADDR_OFF 152
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
#define OB_AUDIT_SQL_CS_TYPE_OFF 344
#define OB_AUDIT_PLAN_ID_OFF 352
#define OB_AUDIT_AFFECTED_ROWS_OFF 360
#define OB_AUDIT_RETURN_ROWS_OFF 368
#define OB_AUDIT_PARTITION_CNT_OFF 376
#define OB_AUDIT_EXPECTED_WORKER_CNT_OFF 384
#define OB_AUDIT_USED_WORKER_CNT_OFF 392
#define OB_AUDIT_TRY_CNT_OFF 400
#define OB_AUDIT_PLAN_TYPE_OFF 408
#define OB_AUDIT_IS_INNER_SQL_OFF (OB_AUDIT_PLAN_TYPE_OFF + 4 + 1)
#define OB_AUDIT_EXEC_TIMESTAMP_OFF 432
#define OB_AUDIT_TRANS_ID_OFF 1320
#define OB_AUDIT_PARAMS_VALUE_LEN_OFF 1352
#define OB_AUDIT_PARAMS_VALUE_PTR_OFF 1360
#define OB_AUDIT_STMT_TYPE_OFF 1684
#define OB_AUDIT_TRANS_STATUS_OFF 1720

/* 连续定长区大小：覆盖所有用到的标量/ptr-len/时间戳偏移(最高 trans_status 1720+4)，
 * 8 字节对齐取 1728。BPF 一次 bulk 读整段到 event.ob_raw，collector 按 OB_*_OFF 解析。 */
#define OB_AUDIT_RAW_FIXED_SIZE 1728

#define OB_EXEC_RPC_SEND_TS_OFF 8
#define OB_EXEC_RECEIVE_TS_OFF 16
#define OB_EXEC_ENTER_QUEUE_TS_OFF 24
#define OB_EXEC_RUN_TS_OFF 32
#define OB_EXEC_BEFORE_PROCESS_TS_OFF 40
#define OB_EXEC_SINGLE_PROCESS_TS_OFF 48
#define OB_EXEC_PROCESS_EXECUTOR_TS_OFF 56
#define OB_EXEC_EXECUTOR_END_TS_OFF 64
#define OB_EXEC_MULTI_STMT_START_TS_OFF 72
#define OB_EXEC_ELAPSED_T_OFF 80
#define OB_EXEC_NET_T_OFF 88
#define OB_EXEC_NET_WAIT_T_OFF 96
#define OB_EXEC_QUEUE_T_OFF 104
#define OB_EXEC_DECODE_T_OFF 112
#define OB_EXEC_GET_PLAN_T_OFF 120
#define OB_EXEC_EXECUTOR_T_OFF 128

#define OB_ADDR_VERSION_OFF 0
#define OB_ADDR_IP_OFF 4
#define OB_ADDR_PORT_OFF 20
#define OB_ADDR_SIZE 24


#define AUDIT_FILE_MAGIC "OBAUDT1"
#define AUDIT_FILE_MAGIC_SIZE 8
#define AUDIT_FILE_VERSION AUDIT_FILE_VERSION_VALUE
#define AUDIT_FLUSH_THRESHOLD (64 * 1024)
#ifndef AUDIT_EVENT_PAYLOAD_SIZE
#define AUDIT_EVENT_PAYLOAD_SIZE (MAX_NAME_LEN + MAX_NAME_LEN + MAX_NAME_LEN + MAX_DB_NAME_LEN + MAX_SQL_LEN + MAX_PARAMS_VALUE_LEN)
#endif

struct audit_file_header {
	char magic[AUDIT_FILE_MAGIC_SIZE];
	unsigned int version;
	unsigned int header_size;
	unsigned int event_size;
	unsigned int reserved;
};

enum ObPhyPlanType
{
  OB_PHY_PLAN_UNINITIALIZED = 0,
  OB_PHY_PLAN_LOCAL,
  OB_PHY_PLAN_REMOTE,
  OB_PHY_PLAN_DISTRIBUTED,
  OB_PHY_PLAN_UNCERTAIN
};

enum ObTransStatus
{
  INVALID_STATUS = 0,
  TRANS_NOT_OPENED = 1,
  IMPLICIT_TRANS = 2,
  COMMIT_TRANS = 3,
};
enum fragment_field {
	FRAG_FIELD_NONE = 0,
	FRAG_FIELD_QUERY_SQL = 1,
	FRAG_FIELD_PARAMS_VALUE = 2,
};

enum fragment_flags {
	FRAG_QUERY_SQL_TRUNCATED = 1 << 0,
	FRAG_PARAMS_VALUE_TRUNCATED = 1 << 1,
	FRAG_QUERY_SQL_FRAGMENTED = 1 << 2,
	FRAG_PARAMS_VALUE_FRAGMENTED = 1 << 3,
	FRAG_LOGICAL_COMPLETE = 1 << 4,
	FRAG_PHYSICAL_COMPLETE = 1 << 5,
	FRAG_USER_LOSS = 1 << 6,
};

struct ob_trace_id_raw {
    unsigned long long uval[4];
};

struct event {
	unsigned int total_size;
	unsigned short record_type;
	unsigned short record_flags;

	unsigned long long event_seq; // 全局递增序号，用于发现丢记录和后续分片关联
	unsigned long long parent_event_seq; // 后续分片事件关联的主事件序号，当前主事件为0
	unsigned long long next_fragment_seq; // 后续分片事件序号，当前暂未生成分片事件

	unsigned long long user_id; // int64_t 
	unsigned long long tenant_id; // int64_t
	unsigned long long effective_tenant_id; // int64_t
	unsigned long long session_id;// 虚拟表字段名：SID uint64_t
	unsigned long long proxy_session_id;// 虚拟表中没有这个字段，但是审计记录中有，proxy_session_id_ uint64_t
	unsigned long long db_id;// uint64_t
	unsigned long long affected_rows;// int64_t
	unsigned long long return_rows;// int64_t
	unsigned long long transaction_hash;// 虚拟表字段名：TX_ID, 审计记录成员变量名：trans_id_
	unsigned long long request_id;//

	// elapsed_time的成员变量receive_ts_ 。 exec_timestamp_.receive_ts_
	long long request_timestamp;// 虚拟表字段名：REQUEST_TIME
	
	// 通过get_elapsed_time()成员函数调用计算得到
	// exec_timestamp_.receive_ts_
	// exec_timestamp_.executor_end_ts_
	// exec_timestamp_.multistmt_start_ts_
	// if (exec_timestamp_.multistmt_start_ts > 0)
	//     elapsed_time = exec_timestamp_.executor_end_ts - exec_timestamp_.multistmt_start_ts;
	// else
	//     elapsed_time = exec_timestamp_.executor_end_ts - exec_timestamp_.receive_ts;
	long long elapsed_time;//

	// 执行时间，sqlaudit record 记录非常详细的各阶段的执行时间在ObExecTimestamp中。成员变量名 ：exec_timestamp_
	long long execute_time; // 
	long long query_sql_len;
	long long params_value_len;

#if AUDIT_PERF_FIELDS_ENABLED
	unsigned long long perf_bpf_entry_ns;
	unsigned long long perf_bpf_before_output_ns;
	unsigned long long perf_agent_receive_ns;
	unsigned long long perf_agent_before_submit_ns;
	unsigned long long perf_agent_after_submit_ns;
	unsigned long long perf_collector_receive_ns;
	unsigned long long perf_mongo_before_insert_ns;
#endif

	struct ob_trace_id_raw trace_id;//

	unsigned int user_name_len;
	unsigned int proxy_user_name_len;
	unsigned int tenant_name_len;
	unsigned int db_name_len;
	unsigned int query_sql_payload_len;
	unsigned int params_value_payload_len;

	int pid;
	int tid;
	int ret_code; //  status_ 成员变量
	int stmt_type; // enum:int_t 32 需要用户态解析，
	enum ObPhyPlanType plan_type; // 
	enum ObTransStatus trans_status;//
	
	unsigned int fragment_flags;
	unsigned int next_fragment_field;

		// user_client_ip/client_ip/server_ip 字段保存 ObAddr 原始二进制，仅 CSV 转换时格式化。
		char user_client_ip[MAX_IP_LEN];// 
		char client_ip[MAX_IP_LEN];//
		char server_ip[MAX_IP_LEN];// BPF 端留空，用户态消费成功后填充本机 agent IP。
		char sql_id[MAX_SQL_ID_LEN];//

	/* OB 审计记录的连续定长区原始拷贝(BPF 一次 bulk 读)。
	 * BPF 端不再逐字段解析标量，collector 从这里按 OB_*_OFF 抽取并回填上面的标量字段。
	 * 注意：payload 必须紧跟其后，event_payload_offset() 依赖 offsetof(payload)。 */
	unsigned char ob_raw[OB_AUDIT_RAW_FIXED_SIZE];

	char payload[AUDIT_EVENT_PAYLOAD_SIZE];
};

static inline unsigned int event_payload_offset(void)
{
	return (unsigned int)__builtin_offsetof(struct event, payload);
}

static inline unsigned int event_payload_len(const struct event *e)
{
	return e->user_name_len + e->proxy_user_name_len + e->tenant_name_len + e->db_name_len +
	       e->query_sql_payload_len + e->params_value_payload_len;
}

static inline int event_compact_size_valid(const struct event *e)
{
	unsigned int payload_offset = event_payload_offset();
	if (e->record_type != AUDIT_RECORD_EVENT)
		return 0;
	if (e->total_size < payload_offset)
		return 0;
	if (e->total_size > sizeof(struct event))
		return 0;
	return payload_offset + event_payload_len(e) == e->total_size;
}

#ifdef __cplusplus
#include <cstdio>
#include <cstring>

static inline const char *event_user_name(const struct event *e)
{
	return e->payload;
}

static inline const char *event_proxy_user_name(const struct event *e)
{
	return e->payload + e->user_name_len;
}

static inline const char *event_tenant_name(const struct event *e)
{
	return e->payload + e->user_name_len + e->proxy_user_name_len;
}

static inline const char *event_db_name(const struct event *e)
{
	return e->payload + e->user_name_len + e->proxy_user_name_len + e->tenant_name_len;
}

static inline const char *event_query_sql(const struct event *e)
{
	return e->payload + e->user_name_len + e->proxy_user_name_len + e->tenant_name_len + e->db_name_len;
}

static inline const char *event_params_value(const struct event *e)
{
	return event_query_sql(e) + e->query_sql_payload_len;
}

/* collector 侧：从 BPF bulk 拷入的 ob_raw 定长区按 OB_*_OFF 抽取标量字段并回填。
 * 复刻原 BPF handle_uprobe 的读取语义(含 elapsed/execute 派生回退)。
 * 不触碰：event_seq/framing/flags/payload 长度(BPF 已填)与 server_ip(agent/collector 填)。 */
static inline void event_fill_scalars_from_ob_raw(struct event *e)
{
	const unsigned char *r = e->ob_raw;
	auto rd_i64 = [r](unsigned int off) { long long v; std::memcpy(&v, r + off, sizeof(v)); return v; };
	auto rd_u64 = [r](unsigned int off) { unsigned long long v; std::memcpy(&v, r + off, sizeof(v)); return v; };
	auto rd_i32 = [r](unsigned int off) { int v; std::memcpy(&v, r + off, sizeof(v)); return v; };

	e->ret_code = rd_i32(OB_AUDIT_STATUS_OFF);
	std::memcpy(&e->trace_id, r + OB_AUDIT_TRACE_ID_OFF, sizeof(e->trace_id));
	e->request_id = rd_u64(OB_AUDIT_REQUEST_ID_OFF);
	e->session_id = rd_u64(OB_AUDIT_SESSION_ID_OFF);
	e->proxy_session_id = rd_u64(OB_AUDIT_PROXY_SESSION_ID_OFF);
	e->tenant_id = rd_u64(OB_AUDIT_TENANT_ID_OFF);
	e->effective_tenant_id = rd_u64(OB_AUDIT_EFFECTIVE_TENANT_ID_OFF);
	e->user_id = rd_u64(OB_AUDIT_USER_ID_OFF);
	e->db_id = rd_u64(OB_AUDIT_DB_ID_OFF);
	e->affected_rows = rd_u64(OB_AUDIT_AFFECTED_ROWS_OFF);
	e->return_rows = rd_u64(OB_AUDIT_RETURN_ROWS_OFF);
	e->transaction_hash = rd_u64(OB_AUDIT_TRANS_ID_OFF);
	e->plan_type = (enum ObPhyPlanType)rd_i32(OB_AUDIT_PLAN_TYPE_OFF);
	e->stmt_type = rd_i32(OB_AUDIT_STMT_TYPE_OFF);
	e->trans_status = (enum ObTransStatus)rd_i32(OB_AUDIT_TRANS_STATUS_OFF);
	std::memcpy(e->sql_id, r + OB_AUDIT_SQL_ID_OFF, sizeof(e->sql_id));

	long long receive_ts = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_RECEIVE_TS_OFF);
	long long process_executor_ts = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_PROCESS_EXECUTOR_TS_OFF);
	long long executor_end_ts = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_EXECUTOR_END_TS_OFF);
	long long multistmt_start_ts = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_MULTI_STMT_START_TS_OFF);
	long long elapsed_t = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_ELAPSED_T_OFF);
	long long executor_t = rd_i64(OB_AUDIT_EXEC_TIMESTAMP_OFF + OB_EXEC_EXECUTOR_T_OFF);
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

	std::memcpy(e->user_client_ip, r + OB_AUDIT_USER_CLIENT_ADDR_OFF, sizeof(e->user_client_ip));
	std::memcpy(e->client_ip, r + OB_AUDIT_CLIENT_ADDR_OFF, sizeof(e->client_ip));
}

static inline bool read_compact_event(FILE *file, struct event *e)
{
	unsigned int total_size = 0;
	if (fread(&total_size, sizeof(total_size), 1, file) != 1)
		return false;
	if (total_size < event_payload_offset() || total_size > sizeof(struct event))
		return false;
	*e = {};
	e->total_size = total_size;
	if (fread((char *)e + sizeof(total_size), total_size - sizeof(total_size), 1, file) != 1)
		return false;
	if (event_compact_size_valid(e) == 0)
		return false;
	// .adt 记录保存的是 BPF 原样输出(标量未解析)，读出后按 ob_raw 回填标量。
	event_fill_scalars_from_ob_raw(e);
	return true;
}
#endif

 
#endif /* __UPROBE_H */
