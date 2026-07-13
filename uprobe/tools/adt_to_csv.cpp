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

#include "uprobe.h"
#include "audit_format.h"

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

static size_t clamp_field_len(long long len, size_t max_len)
{
	if (len <= 0)
		return 0;
	if ((unsigned long long)len > max_len)
		return max_len;
	return (size_t)len;
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

static void write_csv_header(FILE *out)
{
	fprintf(out, "event_seq,parent_event_seq,next_fragment_seq,pid,tid,user_id,tenant_id,effective_tenant_id,session_id,proxy_session_id,db_id,affected_rows,return_rows,transaction_hash,request_id,ret_code,request_timestamp,elapsed_time,execute_time,query_sql_len,params_value_len,stmt_type,stmt_type_name,plan_type,plan_type_name,trans_status,trans_status_name,fragment_flags,next_fragment_field,user_name,proxy_user_name,tenant_name,user_client_ip,client_ip,db_name,sql_id,trace_id,query_sql,params_value\n");
}

static void write_event_csv(FILE *out, const event &e)
{
	fprintf(out, "%llu,%llu,%llu,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d,%lld,%lld,%lld,%lld,%lld,%d,",
		e.event_seq, e.parent_event_seq, e.next_fragment_seq, e.pid, e.tid,
		e.user_id, e.tenant_id, e.effective_tenant_id, e.session_id, e.proxy_session_id,
		e.db_id, e.affected_rows, e.return_rows, e.transaction_hash, e.request_id,
		e.ret_code, e.request_timestamp, e.elapsed_time, e.execute_time,
		e.query_sql_len, e.params_value_len, e.stmt_type);
	write_csv_string(out, stmt_type_to_string(e.stmt_type));
	fprintf(out, ",%d,", e.plan_type);
	write_csv_string(out, plan_type_to_string(e.plan_type));
	fprintf(out, ",%d,", e.trans_status);
	write_csv_string(out, trans_status_to_string(e.trans_status));
	fprintf(out, ",%u,%u,", e.fragment_flags, e.next_fragment_field);
	write_csv_string(out, bounded_string(e.user_name, sizeof(e.user_name)));
	fputc(',', out);
	write_csv_string(out, bounded_string(e.proxy_user_name, sizeof(e.proxy_user_name)));
	fputc(',', out);
	write_csv_string(out, bounded_string(e.tenant_name, sizeof(e.tenant_name)));
	fputc(',', out);
	write_csv_string(out, format_ob_addr(e.user_client_ip, sizeof(e.user_client_ip)));
	fputc(',', out);
	write_csv_string(out, format_ob_addr(e.client_ip, sizeof(e.client_ip)));
	fputc(',', out);
	write_csv_string(out, bounded_string(e.db_name, sizeof(e.db_name)));
	fputc(',', out);
	write_csv_string(out, bounded_string(e.sql_id, sizeof(e.sql_id)));
	fputc(',', out);
	write_csv_string(out, format_trace_id(e.trace_id));
	fputc(',', out);
	write_csv_string(out, std::string(e.query_sql, clamp_field_len(e.query_sql_len, sizeof(e.query_sql))));
	fputc(',', out);
	write_csv_string(out, std::string(e.params_value, clamp_field_len(e.params_value_len, sizeof(e.params_value))));
	fputc('\n', out);
}

static bool get_record_count(FILE *file, unsigned long long *count)
{
	long current = ftell(file);
	if (current < 0)
		return false;
	if (fseek(file, 0, SEEK_END) != 0)
		return false;
	long end = ftell(file);
	if (end < 0)
		return false;
	long data_size = end - (long)sizeof(audit_file_header);
	if (data_size < 0 || data_size % (long)sizeof(event) != 0)
		return false;
	*count = (unsigned long long)(data_size / (long)sizeof(event));
	return fseek(file, current, SEEK_SET) == 0;
}

static bool seek_to_record(FILE *file, unsigned long long index)
{
	unsigned long long offset = sizeof(audit_file_header) + index * sizeof(event);
	return fseek(file, (long)offset, SEEK_SET) == 0;
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

	unsigned long long total_records = 0;
	if (!get_record_count(input, &total_records)) {
		fprintf(stderr, "Failed to get record count\n");
		fclose(input);
		return 1;
	}

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
	if (!seek_to_record(input, start)) {
		fprintf(stderr, "Failed to seek input file\n");
		fclose(output);
		fclose(input);
		return 1;
	}

	event e = {};
	unsigned long long converted = 0;
	while (converted < limit && fread(&e, sizeof(e), 1, input) == 1) {
		write_event_csv(output, e);
		converted++;
	}

	if (ferror(input)) {
		fprintf(stderr, "Failed to read events: %s\n", strerror(errno));
		fclose(output);
		fclose(input);
		return 1;
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
