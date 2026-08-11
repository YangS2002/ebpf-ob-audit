/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AUDIT_RECORD_H
#define __AUDIT_RECORD_H

/* ringbuf 总容量。所有 main event 与 fragment 共用这一个 ringbuf。
 * 64KB SQL/params 分片后可能单条事件约 128KB+，256KB 并发余量太小。
 * 先固定 4MB，后续按丢包率和 grpc 批量策略调整。 */
#define AUDIT_RINGBUF_SIZE (4 * 1024 * 1024)

/* main event 定长 bucket。struct event 头固定 345B，加最大 name 段 316B，
 * 再加 sql 首片 1023B + params 首片 255B = 1939B <= 2048。
 * 只用单一 bucket：reserve 后写入是共享代码，verifier 会按最小 bucket 校验，
 * 多 bucket 会在小 bucket 分支上越界（或复制写入路径导致指令爆炸）。 */
#define AUDIT_RINGBUF_BUCKET_MAIN 2048
#define AUDIT_RINGBUF_MAX_BUCKET AUDIT_RINGBUF_BUCKET_MAIN

/* main event 内 query_sql 段最大字节数。超出部分走 fragment。 */
#define AUDIT_MAIN_SQL_PAYLOAD_MAX 1023

/* main event 内 params_value 段最大字节数。超出部分走 fragment。
 * 收紧到 255 以保证 main 记录整体放进 2048 bucket。 */
#define AUDIT_MAIN_PARAMS_PAYLOAD_MAX 255

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

#define AUDIT_FRAGMENT_HEADER_SIZE ((unsigned int)__builtin_offsetof(struct audit_fragment_record, payload))
#define AUDIT_FRAGMENT_PAYLOAD_MAX 4095
#define AUDIT_FRAGMENT_BUCKET (AUDIT_FRAGMENT_HEADER_SIZE + AUDIT_FRAGMENT_PAYLOAD_MAX + 1)

/* OB 单个 SQL/params 暂按 64KB 捕获阈值。
 * main 1023B + 16 * 4095B = 66543B，覆盖 64KB。 */
#define AUDIT_MAX_FRAGMENTS_PER_FIELD 16
#define AUDIT_CAPTURE_FIELD_MAX (64 * 1024)
#define AUDIT_MAX_FRAGMENTED_FIELD_BYTES (AUDIT_FRAGMENT_PAYLOAD_MAX * AUDIT_MAX_FRAGMENTS_PER_FIELD)
#define AUDIT_SQL_CAPTURE_MAX AUDIT_CAPTURE_FIELD_MAX
#define AUDIT_PARAMS_CAPTURE_MAX AUDIT_CAPTURE_FIELD_MAX

static inline unsigned int audit_fragment_payload_offset(void)
{
	return AUDIT_FRAGMENT_HEADER_SIZE;
}

#endif /* __AUDIT_RECORD_H */
