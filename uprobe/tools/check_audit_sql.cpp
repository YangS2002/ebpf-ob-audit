// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "uprobe.h"

struct expected_sql {
	unsigned long long index;
	std::string original;
	std::string canonical;
};

struct captured_sql {
	unsigned long long event_seq;
	std::string original;
	std::string canonical;
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <event.adt> <expected.sql>\n", prog);
}

static std::string normalize_sql(const std::string &value)
{
	std::string out;
	bool last_space = false;
	for (unsigned char c : value) {
		if (std::isspace(c)) {
			if (!out.empty())
				last_space = true;
			continue;
		}
		if (last_space) {
			out.push_back(' ');
			last_space = false;
		}
		out.push_back(static_cast<char>(std::toupper(c)));
	}
	return out;
}

static std::string remove_all(std::string value, const std::string &needle)
{
	for (;;) {
		size_t pos = value.find(needle);
		if (pos == std::string::npos)
			break;
		value.erase(pos, needle.size());
	}
	return value;
}

static std::string strip_comments(const std::string &value)
{
	std::string out;
	bool in_single_quote = false;
	bool in_double_quote = false;
	bool in_line_comment = false;
	bool in_block_comment = false;

	for (size_t i = 0; i < value.size(); i++) {
		char c = value[i];
		char next = i + 1 < value.size() ? value[i + 1] : '\0';

		if (in_line_comment) {
			if (c == '\n') {
				in_line_comment = false;
				out.push_back(c);
			}
			continue;
		}
		if (in_block_comment) {
			if (c == '*' && next == '/') {
				i++;
				in_block_comment = false;
			}
			continue;
		}
		if (in_single_quote) {
			out.push_back(c);
			if (c == '\\' && next) {
				out.push_back(next);
				i++;
			} else if (c == '\'') {
				in_single_quote = false;
			}
			continue;
		}
		if (in_double_quote) {
			out.push_back(c);
			if (c == '\\' && next) {
				out.push_back(next);
				i++;
			} else if (c == '"') {
				in_double_quote = false;
			}
			continue;
		}
		if (c == '-' && next == '-') {
			in_line_comment = true;
			i++;
			continue;
		}
		if (c == '/' && next == '*') {
			in_block_comment = true;
			i++;
			continue;
		}
		if (c == '\'')
			in_single_quote = true;
		else if (c == '"')
			in_double_quote = true;
		out.push_back(c);
	}
	return out;
}

static std::string canonical_sql(const std::string &value)
{
	std::string out = normalize_sql(strip_comments(value));
	out = remove_all(out, "`");
	out = remove_all(out, ";");
	out = remove_all(out, " ");
	return out;
}

static std::string load_file_text(const char *path)
{
	std::ifstream in(path);
	std::string text;
	std::string line;
	while (std::getline(in, line)) {
		text += line;
		text.push_back('\n');
	}
	return text;
}

static std::vector<std::string> split_sql_statements(const std::string &text)
{
	std::vector<std::string> statements;
	std::string statement;
	bool in_single_quote = false;
	bool in_double_quote = false;
	bool in_line_comment = false;
	bool in_block_comment = false;

	for (size_t i = 0; i < text.size(); i++) {
		char c = text[i];
		char next = i + 1 < text.size() ? text[i + 1] : '\0';
		statement.push_back(c);

		if (in_line_comment) {
			if (c == '\n')
				in_line_comment = false;
			continue;
		}
		if (in_block_comment) {
			if (c == '*' && next == '/') {
				statement.push_back(next);
				i++;
				in_block_comment = false;
			}
			continue;
		}
		if (in_single_quote) {
			if (c == '\\' && next) {
				statement.push_back(next);
				i++;
			} else if (c == '\'') {
				in_single_quote = false;
			}
			continue;
		}
		if (in_double_quote) {
			if (c == '\\' && next) {
				statement.push_back(next);
				i++;
			} else if (c == '"') {
				in_double_quote = false;
			}
			continue;
		}
		if (c == '-' && next == '-') {
			in_line_comment = true;
			continue;
		}
		if (c == '/' && next == '*') {
			statement.push_back(next);
			i++;
			in_block_comment = true;
			continue;
		}
		if (c == '\'') {
			in_single_quote = true;
			continue;
		}
		if (c == '"') {
			in_double_quote = true;
			continue;
		}
		if (c == ';') {
			statements.push_back(statement);
			statement.clear();
		}
	}
	if (!canonical_sql(statement).empty())
		statements.push_back(statement);
	return statements;
}

static std::vector<expected_sql> load_expected_sqls(const char *path)
{
	std::vector<expected_sql> expected;
	std::string text = load_file_text(path);
	unsigned long long index = 0;
	for (const auto &statement : split_sql_statements(text)) {
		std::string canonical = canonical_sql(statement);
		if (canonical.empty())
			continue;
		index++;
		expected.push_back({index, normalize_sql(statement), canonical});
	}
	return expected;
}

static bool read_header(FILE *file)
{
	audit_file_header header = {};
	if (fread(&header, sizeof(header), 1, file) != 1) {
		fprintf(stderr, "Failed to read file header: %s\n", strerror(errno));
		return false;
	}
	if (memcmp(header.magic, AUDIT_FILE_MAGIC, sizeof(AUDIT_FILE_MAGIC)) != 0) {
		fprintf(stderr, "Invalid file magic\n");
		return false;
	}
	if (header.version != AUDIT_FILE_VERSION) {
		fprintf(stderr, "Unsupported file version: %u\n", header.version);
		return false;
	}
	if (header.event_size != sizeof(event)) {
		fprintf(stderr, "Invalid event size: %u expected=%zu\n", header.event_size, sizeof(event));
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		usage(argv[0]);
		return 1;
	}

	std::vector<expected_sql> expected = load_expected_sqls(argv[2]);
	if (expected.empty()) {
		fprintf(stderr, "No SQL statements found in %s\n", argv[2]);
		return 1;
	}

	FILE *file = fopen(argv[1], "rb");
	if (!file) {
		fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}
	if (!read_header(file)) {
		fclose(file);
		return 1;
	}

	std::vector<captured_sql> captured;
	unsigned long long total_events = 0;
	event e = {};
	while (fread(&e, sizeof(e), 1, file) == 1) {
		total_events++;
		std::string sql(e.query_sql);
		std::string canonical = canonical_sql(sql);
		if (!canonical.empty())
			captured.push_back({e.event_seq, normalize_sql(sql), canonical});
	}
	fclose(file);

	std::vector<expected_sql> missing;
	std::vector<std::pair<expected_sql, captured_sql>> matched;
	for (const auto &sql : expected) {
		bool found = false;
		for (const auto &captured_sql : captured) {
			if (captured_sql.canonical.find(sql.canonical) != std::string::npos ||
			    sql.canonical.find(captured_sql.canonical) != std::string::npos) {
				found = true;
				matched.push_back({sql, captured_sql});
				break;
			}
		}
		if (!found)
			missing.push_back(sql);
	}

	fprintf(stderr, "events=%llu expected_sql=%zu captured_sql=%zu matched=%zu missing=%zu\n",
		total_events, expected.size(), captured.size(), matched.size(), missing.size());

	if (!matched.empty()) {
		fprintf(stderr, "Matched SQL statements:\n");
		for (const auto &item : matched) {
			fprintf(stderr, "[%llu] event_seq=%llu expected=%s\n", item.first.index,
				item.second.event_seq, item.first.original.c_str());
			fprintf(stderr, "     captured=%s\n", item.second.original.c_str());
		}
	}

	if (!missing.empty()) {
		fprintf(stderr, "Missing SQL statements:\n");
		for (const auto &sql : missing) {
			fprintf(stderr, "[%llu] %s\n", sql.index, sql.original.c_str());
		}
		return 1;
	}

	fprintf(stderr, "PASS: all expected SQL statements captured\n");
	return 0;
}
