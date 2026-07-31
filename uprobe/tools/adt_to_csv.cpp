// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Usage:
//   Build:
//     make -C uprobe tools
//
//   Convert all records:
//     ./uprobe/bin/adt_to_csv <input.adt> <output.csv> all
//
//   Convert first N records:
//     ./uprobe/bin/adt_to_csv <input.adt> <output.csv> head <N>
//
//   Convert last N records:
//     ./uprobe/bin/adt_to_csv <input.adt> <output.csv> tail <N>
//
// Examples:
//   ./uprobe/bin/adt_to_csv audit_events.dat audit_events.csv all
//   ./uprobe/bin/adt_to_csv audit_events.dat audit_head100.csv head 100
//   ./uprobe/bin/adt_to_csv audit_events.dat audit_tail100.csv tail 100
//
// Notes:
//   This tool writes CSV to <output.csv>. It does not print records to stdout,
//   so large .adt files will not block or flood the terminal.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "uprobe.h"
#include "audit_format.h"

struct CsvField {
	const char *name;
	void (*write)(FILE *out, const event &e);
};

static void write_csv_header(FILE *out);
static void write_event_csv(FILE *out, const event &e);

#define DEFINE_U64_FIELD_WRITER(writer_name, member) \
static void writer_name(FILE *out, const event &e) \
{ \
	fprintf(out, "%llu", e.member); \
}

#define DEFINE_I64_FIELD_WRITER(writer_name, member) \
static void writer_name(FILE *out, const event &e) \
{ \
	fprintf(out, "%lld", e.member); \
}

#define DEFINE_I32_FIELD_WRITER(writer_name, member) \
static void writer_name(FILE *out, const event &e) \
{ \
	fprintf(out, "%d", e.member); \
}

#define DEFINE_U32_FIELD_WRITER(writer_name, member) \
static void writer_name(FILE *out, const event &e) \
{ \
	fprintf(out, "%u", e.member); \
}

enum class Mode {
	ALL,
	HEAD,
	TAIL,
};

struct Options {
	const char *input_path = nullptr;
	const char *output_path = nullptr;
	Mode mode = Mode::ALL;
	unsigned long long limit = 0;
};

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s <input.adt> <output.csv> all\n"
		"  %s <input.adt> <output.csv> head <N>\n"
		"  %s <input.adt> <output.csv> tail <N>\n",
		prog, prog, prog);
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

static unsigned long long parse_count(const char *arg)
{
	char *end = nullptr;
	errno = 0;
	unsigned long long value = strtoull(arg, &end, 10);
	if (errno || *end != '\0') {
		fprintf(stderr, "Invalid count: %s\n", arg);
		exit(1);
	}
	return value;
}

static bool parse_options(int argc, char **argv, Options *opts)
{
	if (argc != 4 && argc != 5)
		return false;

	opts->input_path = argv[1];
	opts->output_path = argv[2];

	if (strcmp(argv[3], "all") == 0) {
		if (argc != 4)
			return false;
		opts->mode = Mode::ALL;
		return true;
	}

	if (argc != 5)
		return false;

	if (strcmp(argv[3], "head") == 0) {
		opts->mode = Mode::HEAD;
		opts->limit = parse_count(argv[4]);
		return true;
	}
	if (strcmp(argv[3], "tail") == 0) {
		opts->mode = Mode::TAIL;
		opts->limit = parse_count(argv[4]);
		return true;
	}

	return false;
}

static std::string bounded_string(const char *data, size_t max_len)
{
	size_t len = 0;
	while (len < max_len && data[len] != '\0')
		len++;
	return std::string(data, len);
}

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

static std::string format_trace_id(const ob_trace_id_raw &trace_id)
{
	char buf[128] = {};
	unsigned long long u0 = trace_id.uval[0];
	unsigned int bytes_no_ip = (unsigned int)(u0 >> 32);
	bool is_ipv6 = ((bytes_no_ip >> 17) & 0x1) != 0;
	if (!is_ipv6) {
		snprintf(buf, sizeof(buf), "Y%llX-%016llX-%llX-%llX",
			trace_id.uval[0], trace_id.uval[1], trace_id.uval[2], trace_id.uval[3]);
	} else {
		snprintf(buf, sizeof(buf), "Y%X-%016llX-%llX-%llX",
			bytes_no_ip, trace_id.uval[1], trace_id.uval[2], trace_id.uval[3]);
	}
	return std::string(buf);
}


static void write_csv_string(FILE *out, const std::string &s)
{
	fputc('"', out);
	for (char c : s) {
		if (c == '"') {
			fputc('"', out);
			fputc('"', out);
		} else if (c == '\n' || c == '\r' || c == '\t') {
			fputc(' ', out);
		} else {
			fputc(c, out);
		}
	}
	fputc('"', out);
}

DEFINE_U64_FIELD_WRITER(write_event_seq, event_seq)
DEFINE_U64_FIELD_WRITER(write_parent_event_seq, parent_event_seq)
DEFINE_U64_FIELD_WRITER(write_next_fragment_seq, next_fragment_seq)
DEFINE_I32_FIELD_WRITER(write_pid, pid)
DEFINE_I32_FIELD_WRITER(write_tid, tid)
DEFINE_U64_FIELD_WRITER(write_user_id, user_id)
DEFINE_U64_FIELD_WRITER(write_tenant_id, tenant_id)
DEFINE_U64_FIELD_WRITER(write_effective_tenant_id, effective_tenant_id)
DEFINE_U64_FIELD_WRITER(write_session_id, session_id)
DEFINE_U64_FIELD_WRITER(write_proxy_session_id, proxy_session_id)
DEFINE_U64_FIELD_WRITER(write_db_id, db_id)
DEFINE_U64_FIELD_WRITER(write_affected_rows, affected_rows)
DEFINE_U64_FIELD_WRITER(write_return_rows, return_rows)
DEFINE_U64_FIELD_WRITER(write_transaction_hash, transaction_hash)
DEFINE_U64_FIELD_WRITER(write_request_id, request_id)
DEFINE_I32_FIELD_WRITER(write_ret_code, ret_code)
DEFINE_I64_FIELD_WRITER(write_request_timestamp, request_timestamp)
DEFINE_I64_FIELD_WRITER(write_elapsed_time, elapsed_time)
DEFINE_I64_FIELD_WRITER(write_execute_time, execute_time)
DEFINE_I64_FIELD_WRITER(write_query_sql_len, query_sql_len)
DEFINE_I64_FIELD_WRITER(write_params_value_len, params_value_len)
#if AUDIT_PERF_FIELDS_ENABLED
DEFINE_U64_FIELD_WRITER(write_perf_bpf_entry_ns, perf_bpf_entry_ns)
DEFINE_U64_FIELD_WRITER(write_perf_bpf_before_output_ns, perf_bpf_before_output_ns)
DEFINE_U64_FIELD_WRITER(write_perf_agent_receive_ns, perf_agent_receive_ns)
DEFINE_U64_FIELD_WRITER(write_perf_agent_before_submit_ns, perf_agent_before_submit_ns)
DEFINE_U64_FIELD_WRITER(write_perf_agent_after_submit_ns, perf_agent_after_submit_ns)
DEFINE_U64_FIELD_WRITER(write_perf_collector_receive_ns, perf_collector_receive_ns)
DEFINE_U64_FIELD_WRITER(write_perf_mongo_before_insert_ns, perf_mongo_before_insert_ns)
#endif
DEFINE_I32_FIELD_WRITER(write_stmt_type, stmt_type)
DEFINE_I32_FIELD_WRITER(write_plan_type, plan_type)

static const char *trans_status_to_ob_sql_audit_string(int trans_status)
{
	switch (trans_status) {
	case 1:
		return "Transaction not opened";
	case 2:
		return "Enable implicit transactions";
	case 3:
		return "Enable committable transaction";
	default:
		return "Unknown status";
	}
}

static void write_trans_status(FILE *out, const event &e)
{
	write_csv_string(out, trans_status_to_ob_sql_audit_string(e.trans_status));
}

DEFINE_U32_FIELD_WRITER(write_fragment_flags, fragment_flags)
DEFINE_U32_FIELD_WRITER(write_next_fragment_field, next_fragment_field)

static void write_stmt_type_name(FILE *out, const event &e)
{
	write_csv_string(out, stmt_type_to_string(e.stmt_type));
}

static void write_plan_type_name(FILE *out, const event &e)
{
	write_csv_string(out, plan_type_to_string(e.plan_type));
}

static void write_trans_status_name(FILE *out, const event &e)
{
	write_csv_string(out, trans_status_to_ob_sql_audit_string(e.trans_status));
}

static void write_user_name(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_user_name(&e), e.user_name_len));
}

static void write_proxy_user_name(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_proxy_user_name(&e), e.proxy_user_name_len));
}

static void write_tenant_name(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_tenant_name(&e), e.tenant_name_len));
}

static void write_user_client_ip(FILE *out, const event &e)
{
	write_csv_string(out, format_ob_addr(e.user_client_ip, sizeof(e.user_client_ip)));
}

static void write_client_ip(FILE *out, const event &e)
{
	write_csv_string(out, format_ob_addr(e.client_ip, sizeof(e.client_ip)));
}

static void write_server_ip(FILE *out, const event &e)
{
	write_csv_string(out, format_ob_addr(e.server_ip, sizeof(e.server_ip)));
}

static void write_db_name(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_db_name(&e), e.db_name_len));
}

static void write_sql_id(FILE *out, const event &e)
{
	write_csv_string(out, bounded_string(e.sql_id, sizeof(e.sql_id)));
}

static void write_trace_id(FILE *out, const event &e)
{
	write_csv_string(out, format_trace_id(e.trace_id));
}

static void write_query_sql(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_query_sql(&e), e.query_sql_payload_len));
}

static void write_params_value(FILE *out, const event &e)
{
	write_csv_string(out, std::string(event_params_value(&e), e.params_value_payload_len));
}

static const CsvField CSV_FIELDS[] = {
	{"event_seq", write_event_seq},
	{"parent_event_seq", write_parent_event_seq},
	{"next_fragment_seq", write_next_fragment_seq},
	{"pid", write_pid},
	{"tid", write_tid},
	{"user_id", write_user_id},
	{"tenant_id", write_tenant_id},
	{"effective_tenant_id", write_effective_tenant_id},
	{"session_id", write_session_id},
	{"proxy_session_id", write_proxy_session_id},
	{"db_id", write_db_id},
	{"affected_rows", write_affected_rows},
	{"return_rows", write_return_rows},
	{"transaction_hash", write_transaction_hash},
	{"request_id", write_request_id},
	{"ret_code", write_ret_code},
	{"request_timestamp", write_request_timestamp},
	{"elapsed_time", write_elapsed_time},
	{"execute_time", write_execute_time},
	{"query_sql_len", write_query_sql_len},
	{"params_value_len", write_params_value_len},
#if AUDIT_PERF_FIELDS_ENABLED
	{"perf_bpf_entry_ns", write_perf_bpf_entry_ns},
	{"perf_bpf_before_output_ns", write_perf_bpf_before_output_ns},
	{"perf_agent_receive_ns", write_perf_agent_receive_ns},
	{"perf_agent_before_submit_ns", write_perf_agent_before_submit_ns},
	{"perf_agent_after_submit_ns", write_perf_agent_after_submit_ns},
	{"perf_collector_receive_ns", write_perf_collector_receive_ns},
	{"perf_mongo_before_insert_ns", write_perf_mongo_before_insert_ns},
#endif
	{"stmt_type_value", write_stmt_type},
	{"stmt_type", write_stmt_type_name},
	{"plan_type", write_plan_type},
	{"plan_type_name", write_plan_type_name},
	{"trans_status", write_trans_status},
	{"trans_status_name", write_trans_status_name},
	{"fragment_flags", write_fragment_flags},
	{"next_fragment_field", write_next_fragment_field},
	{"user_name", write_user_name},
	{"proxy_user_name", write_proxy_user_name},
	{"tenant_name", write_tenant_name},
	{"user_client_ip", write_user_client_ip},
	{"client_ip", write_client_ip},
	{"server_ip", write_server_ip},
	{"db_name", write_db_name},
	{"sql_id", write_sql_id},
	{"trace_id", write_trace_id},
	{"query_sql", write_query_sql},
	{"params_value", write_params_value},
};

static void write_csv_header(FILE *out)
{
	for (size_t i = 0; i < sizeof(CSV_FIELDS) / sizeof(CSV_FIELDS[0]); i++) {
		if (i > 0)
			fputc(',', out);
		fputs(CSV_FIELDS[i].name, out);
	}
	fputc('\n', out);
}

static void write_event_csv(FILE *out, const event &e)
{
	for (size_t i = 0; i < sizeof(CSV_FIELDS) / sizeof(CSV_FIELDS[0]); i++) {
		if (i > 0)
			fputc(',', out);
		CSV_FIELDS[i].write(out, e);
	}
	fputc('\n', out);
}

// 合并后事件为变长，total_size 可超过 sizeof(struct event)，故不能用 read_compact_event。
static const unsigned int ADT_RECORD_MAX =
	(unsigned int)sizeof(event) + AUDIT_SQL_CAPTURE_MAX + AUDIT_PARAMS_CAPTURE_MAX;

static bool variable_event_valid(const event *e, unsigned int total_size)
{
	if (e->record_type != AUDIT_RECORD_EVENT)
		return false;
	if (total_size < event_payload_offset())
		return false;
	return event_payload_offset() + event_payload_len(e) == total_size;
}

// 变长读取：每条记录自带 total_size 头，读入按 total_size 分配的堆缓冲。
static bool read_variable_event(FILE *file, std::vector<char> *buf)
{
	unsigned int total_size = 0;
	if (fread(&total_size, sizeof(total_size), 1, file) != 1)
		return false;
	if (total_size < event_payload_offset() || total_size > ADT_RECORD_MAX)
		return false;
	buf->assign(total_size, 0);
	memcpy(buf->data(), &total_size, sizeof(total_size));
	if (fread(buf->data() + sizeof(total_size), total_size - sizeof(total_size), 1, file) != 1)
		return false;
	return variable_event_valid(reinterpret_cast<const event *>(buf->data()), total_size);
}

static bool load_events(FILE *file, std::vector<std::vector<char>> *events)
{
	std::vector<char> buf;
	while (read_variable_event(file, &buf))
		events->push_back(std::move(buf));
	return !ferror(file);
}

int main(int argc, char **argv)
{
	Options opts;
	if (!parse_options(argc, argv, &opts)) {
		print_usage(argv[0]);
		return 1;
	}

	FILE *input = fopen(opts.input_path, "rb");
	if (!input) {
		fprintf(stderr, "Failed to open %s: %s\n", opts.input_path, strerror(errno));
		return 1;
	}

	audit_file_header header = {};
	if (!read_header(input, &header)) {
		fclose(input);
		return 1;
	}

	std::vector<std::vector<char>> events;
	if (!load_events(input, &events)) {
		fprintf(stderr, "Failed to read events: %s\n", strerror(errno));
		fclose(input);
		return 1;
	}
	unsigned long long total_records = events.size();

	unsigned long long start = 0;
	unsigned long long limit = total_records;
	if (opts.mode == Mode::HEAD) {
		limit = opts.limit < total_records ? opts.limit : total_records;
	} else if (opts.mode == Mode::TAIL) {
		limit = opts.limit < total_records ? opts.limit : total_records;
		start = total_records - limit;
	}

	FILE *output = fopen(opts.output_path, "w");
	if (!output) {
		fprintf(stderr, "Failed to open %s: %s\n", opts.output_path, strerror(errno));
		fclose(input);
		return 1;
	}

	write_csv_header(output);

	unsigned long long converted = 0;
	for (unsigned long long i = start; converted < limit && i < total_records; i++) {
		write_event_csv(output, *reinterpret_cast<const event *>(events[(size_t)i].data()));
		converted++;
	}

	if (fclose(output) != 0) {
		fprintf(stderr, "Failed to close %s: %s\n", opts.output_path, strerror(errno));
		fclose(input);
		return 1;
	}
	fclose(input);

	fprintf(stderr, "converted=%llu total=%llu output=%s\n", converted, total_records, opts.output_path);
	return 0;
}
