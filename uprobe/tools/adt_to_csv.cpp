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

#include "uprobe.h"

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

static void write_csv_string(FILE *out, const char *s)
{
	fputc('"', out);
	for (const char *p = s; *p; p++) {
		if (*p == '"') {
			fputc('"', out);
			fputc('"', out);
		} else if (*p == '\n' || *p == '\r' || *p == '\t') {
			fputc(' ', out);
		} else {
			fputc(*p, out);
		}
	}
	fputc('"', out);
}

static void write_csv_header(FILE *out)
{
	fprintf(out, "event_seq,parent_event_seq,next_fragment_seq,pid,tid,user_id,tenant_id,effective_tenant_id,session_id,proxy_session_id,db_id,affected_rows,return_rows,transaction_hash,request_id,ret_code,request_timestamp,elapsed_time,execute_time,query_sql_len,params_value_len,stmt_type,plan_type,trans_status,fragment_flags,next_fragment_field,user_name,proxy_user_name,tenant_name,user_client_ip,client_ip,db_name,sql_id,trace_id_0,trace_id_1,trace_id_2,trace_id_3,query_sql,params_value\n");
}

static void write_event_csv(FILE *out, const event &e)
{
	fprintf(out, "%llu,%llu,%llu,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d,%lld,%lld,%lld,%lld,%lld,%d,%d,%d,%u,%u,",
		e.event_seq, e.parent_event_seq, e.next_fragment_seq, e.pid, e.tid,
		e.user_id, e.tenant_id, e.effective_tenant_id, e.session_id, e.proxy_session_id,
		e.db_id, e.affected_rows, e.return_rows, e.transaction_hash, e.request_id,
		e.ret_code, e.request_timestamp, e.elapsed_time, e.execute_time,
		e.query_sql_len, e.params_value_len, e.stmt_type, e.plan_type, e.trans_status,
		e.fragment_flags, e.next_fragment_field);
	write_csv_string(out, e.user_name);
	fputc(',', out);
	write_csv_string(out, e.proxy_user_name);
	fputc(',', out);
	write_csv_string(out, e.tenant_name);
	fputc(',', out);
	write_csv_string(out, e.user_client_ip);
	fputc(',', out);
	write_csv_string(out, e.client_ip);
	fputc(',', out);
	write_csv_string(out, e.db_name);
	fputc(',', out);
	write_csv_string(out, e.sql_id);
	fprintf(out, ",%llu,%llu,%llu,%llu,",
		e.trace_id.uval[0], e.trace_id.uval[1], e.trace_id.uval[2], e.trace_id.uval[3]);
	write_csv_string(out, e.query_sql);
	fputc(',', out);
	write_csv_string(out, e.params_value);
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
