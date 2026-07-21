// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "uprobe.h"

static int append_dec_u8(char *dst, int pos, unsigned char v)
{
	if (v >= 100) {
		dst[pos++] = '0' + v / 100;
		dst[pos++] = '0' + (v / 10) % 10;
		dst[pos++] = '0' + v % 10;
	} else if (v >= 10) {
		dst[pos++] = '0' + v / 10;
		dst[pos++] = '0' + v % 10;
	} else {
		dst[pos++] = '0' + v;
	}
	return pos;
}

static std::string format_ob_addr(const char *data, size_t max_len)
{
	if (max_len < OB_ADDR_SIZE)
		return "";
	int version = 0;
	unsigned int ip = 0;
	memcpy(&version, data + OB_ADDR_VERSION_OFF, sizeof(version));
	if (version != 4)
		return "";
	memcpy(&ip, data + OB_ADDR_IP_OFF, sizeof(ip));
	if (ip == 0)
		return "";
	char buf[16] = {};
	int pos = 0;
	pos = append_dec_u8(buf, pos, (ip >> 24) & 0xff);
	buf[pos++] = '.';
	pos = append_dec_u8(buf, pos, (ip >> 16) & 0xff);
	buf[pos++] = '.';
	pos = append_dec_u8(buf, pos, (ip >> 8) & 0xff);
	buf[pos++] = '.';
	pos = append_dec_u8(buf, pos, ip & 0xff);
	buf[pos] = '\0';
	return std::string(buf);
}
static std::string field_string(const char *data, unsigned int len)
{
	return std::string(data, len);
}

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
		fprintf(stderr, "Unsupported file version: %u expected=%u\n", header->version, AUDIT_FILE_VERSION);
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
	std::string db_name = field_string(event_db_name(&e), e.db_name_len);
	std::string user_name = field_string(event_user_name(&e), e.user_name_len);
	std::string proxy_user_name = field_string(event_proxy_user_name(&e), e.proxy_user_name_len);
	std::string tenant_name = field_string(event_tenant_name(&e), e.tenant_name_len);
	std::string user_client_ip = format_ob_addr(e.user_client_ip, sizeof(e.user_client_ip));
	std::string client_ip = format_ob_addr(e.client_ip, sizeof(e.client_ip));
	std::string server_ip = format_ob_addr(e.server_ip, sizeof(e.server_ip));
	std::string sql_id(e.sql_id, sizeof(e.sql_id));
	std::string query_sql(event_query_sql(&e), e.query_sql_payload_len);
	std::string params_value(event_params_value(&e), e.params_value_payload_len);

	printf("seq=%llu parent=%llu next=%llu pid=%d tid=%d tenant_id=%llu user_id=%llu session_id=%llu request_id=%llu ret_code=%d stmt_type=%d plan_type=%d trans_status=%d request_ts=%lld elapsed=%lld execute=%lld affected_rows=%llu return_rows=%llu db_id=%llu db=%s user=%s proxy_user=%s tenant=%s user_client_ip=%s client_ip=%s server_ip=%s sql_id=%s sql_len=%lld params_len=%lld flags=0x%x next_field=%u trace_id=%llx:%llx:%llx:%llx sql=%s params=%s\n",
	       e.event_seq, e.parent_event_seq, e.next_fragment_seq,
	       e.pid, e.tid,
	       e.tenant_id, e.user_id, e.session_id, e.request_id,
	       e.ret_code, e.stmt_type, e.plan_type, e.trans_status,
	       e.request_timestamp, e.elapsed_time, e.execute_time,
	       e.affected_rows, e.return_rows, e.db_id,
	       db_name.c_str(), user_name.c_str(), proxy_user_name.c_str(), tenant_name.c_str(),
	       user_client_ip.c_str(), client_ip.c_str(), server_ip.c_str(), sql_id.c_str(),
	       e.query_sql_len, e.params_value_len,
	       e.fragment_flags, e.next_fragment_field,
	       e.trace_id.uval[0], e.trace_id.uval[1], e.trace_id.uval[2], e.trace_id.uval[3],
	       query_sql.c_str(), params_value.c_str());
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

	while (read_compact_event(file, &e)) {
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
		total_bytes += e.total_size;
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
