/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AUDIT_RECORD_H
#define __AUDIT_RECORD_H

/* ringbuf 总容量。所有 main event 与 fragment 共用这一个 ringbuf。
 * 64KB SQL/params 分片后可能单条事件约 128KB+，256KB 并发余量太小。
 * 先固定 4MB，后续按丢包率和 grpc 批量策略调整。 */
#define AUDIT_RINGBUF_SIZE (4 * 1024 * 1024)

/* main event 内 query_sql 段最大字节数。超出部分走 fragment。
 * main event 保持小块，避免 per-cpu event_scratch 过大。 */
#define AUDIT_MAIN_SQL_PAYLOAD_MAX 1023

/* main event 内 params_value 段最大字节数。同上。 */
#define AUDIT_MAIN_PARAMS_PAYLOAD_MAX 1023

/* 单个 fragment 的 payload 最大字节数。
 * 固定约 4KB 分片：4095 是 2^12-1，便于 verifier 用 mask 证明长度非负有界。
 * 加上 44B fragment header 后，per-cpu fragment scratch 约 4KB。 */
#define AUDIT_FRAGMENT_PAYLOAD_MAX 4095

/* OB 单个 SQL/params 暂按 64KB 捕获阈值。
 * 计算片数：main 1023B + 16 * 4095B = 66543B，覆盖 64KB。 */
#define AUDIT_MAX_FRAGMENTS_PER_FIELD 16
#define AUDIT_CAPTURE_FIELD_MAX (64 * 1024)
#define AUDIT_MAX_FRAGMENTED_FIELD_BYTES (AUDIT_FRAGMENT_PAYLOAD_MAX * AUDIT_MAX_FRAGMENTS_PER_FIELD)
#define AUDIT_SQL_CAPTURE_MAX AUDIT_CAPTURE_FIELD_MAX
#define AUDIT_PARAMS_CAPTURE_MAX AUDIT_CAPTURE_FIELD_MAX

enum audit_record_type {
	AUDIT_RECORD_EVENT = 1,
	AUDIT_RECORD_FRAGMENT = 2,
};

enum audit_record_flags {
	AUDIT_RECORD_FLAG_LOGICAL_COMPLETE = 1 << 0,
	AUDIT_RECORD_FLAG_PHYSICAL_COMPLETE = 1 << 1,
	AUDIT_RECORD_FLAG_FRAGMENT = 1 << 2,
	AUDIT_RECORD_FLAG_LAST_FRAGMENT = 1 << 3,
};

struct audit_record_header {
	unsigned int total_size;
	unsigned short record_type;
	unsigned short record_flags;
};

struct audit_fragment_record {
	unsigned int total_size;
	unsigned short record_type;
	unsigned short record_flags;
	unsigned long long event_seq;
	unsigned long long parent_event_seq;
	unsigned long long next_fragment_seq;
	unsigned int field;
	unsigned int fragment_offset;
	unsigned int payload_len;
	char payload[0];
};

static inline unsigned int audit_fragment_payload_offset(void)
{
	return (unsigned int)__builtin_offsetof(struct audit_fragment_record, payload);
}

#endif /* __AUDIT_RECORD_H */
