// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "uprobe.h"

static bool read_header(FILE *file, audit_file_header *header)
{
	if (fread(header, sizeof(*header), 1, file) != 1) {
		fprintf(stderr, "Failed to read file header: %s\n", strerror(errno));
		return false;
	}
	if (memcmp(header->magic, AUDIT_FILE_MAGIC, sizeof(AUDIT_FILE_MAGIC)) != 0) {
		fprintf(stderr, "Invalid file magic\n");
		return false;
	}
	if (header->version != AUDIT_FILE_VERSION) {
		fprintf(stderr, "Unsupported file version: %u\n", header->version);
		return false;
	}
	if (header->header_size != sizeof(*header)) {
		fprintf(stderr, "Invalid header size: %u expected=%zu\n", header->header_size, sizeof(*header));
		return false;
	}
	if (header->event_size != sizeof(event)) {
		fprintf(stderr, "Invalid event size: %u expected=%zu\n", header->event_size, sizeof(event));
		return false;
	}
	return true;
}

static void print_event(const event &e)
{
	printf("seq=%llu parent=%llu next=%llu pid=%d tid=%d comm=%s tenant_id=%llu user_id=%llu session_id=%llu request_id=%llu ret_code=%d stmt_type=%d plan_type=%d trans_status=%d request_ts=%lld elapsed=%lld affected_rows=%llu return_rows=%llu db_id=%llu db=%s user=%s tenant=%s sql_id=%s sql_len=%lld params_len=%lld flags=0x%x next_field=%u trace_id=%llx:%llx:%llx:%llx sql=%s params=%s\n",
	       e.event_seq, e.parent_event_seq, e.next_fragment_seq,
	       e.pid, e.tid, e.comm,
	       e.tenant_id, e.user_id, e.session_id, e.request_id,
	       e.ret_code, e.stmt_type, e.plan_type, e.trans_status,
	       e.request_timestamp, e.elapsed_time,
	       e.affected_rows, e.return_rows, e.db_id,
	       e.db_name, e.user_name, e.tenant_name, e.sql_id,
	       e.query_sql_len, e.params_value_len,
	       e.fragment_flags, e.next_fragment_field,
	       e.trace_id.uval[0], e.trace_id.uval[1], e.trace_id.uval[2], e.trace_id.uval[3],
	       e.query_sql, e.params_value);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <event-file>\n", argv[0]);
		return 1;
	}

	FILE *file = fopen(argv[1], "rb");
	if (!file) {
		fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	audit_file_header header = {};
	if (!read_header(file, &header)) {
		fclose(file);
		return 1;
	}

	event e = {};
	unsigned long long total_records = 0;
	unsigned long long total_bytes = 0;
	unsigned long long sql_truncated = 0;
	unsigned long long params_truncated = 0;
	unsigned long long sequence_gaps = 0;
	unsigned long long expected_seq = 0;

	while (fread(&e, sizeof(e), 1, file) == 1) {
		if (expected_seq && e.event_seq != expected_seq) {
			sequence_gaps++;
			printf("sequence_gap: expected=%llu actual=%llu\n", expected_seq, e.event_seq);
		}
		expected_seq = e.event_seq + 1;
		if (e.fragment_flags & FRAG_QUERY_SQL_TRUNCATED)
			sql_truncated++;
		if (e.fragment_flags & FRAG_PARAMS_VALUE_TRUNCATED)
			params_truncated++;
		total_records++;
		total_bytes += sizeof(e);
		print_event(e);
	}

	if (ferror(file)) {
		fprintf(stderr, "Failed to read events: %s\n", strerror(errno));
		fclose(file);
		return 1;
	}

	printf("summary: records=%llu bytes=%llu sql_truncated=%llu params_truncated=%llu sequence_gaps=%llu\n",
	       total_records, total_bytes, sql_truncated, params_truncated, sequence_gaps);
	fclose(file);
	return 0;
}
