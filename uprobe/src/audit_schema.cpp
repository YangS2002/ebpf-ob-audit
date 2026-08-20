// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_schema.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#if __has_include(<bson/bson.h>)
#define HAVE_BSON 1
#include <bson/bson.h>
#elif __has_include(<mongoc/mongoc.h>)
#define HAVE_BSON 1
#include <mongoc/mongoc.h>
#else
#define HAVE_BSON 0
#endif

static bool read_file_to_string(const std::string &path, std::string *out, std::string *error)
{
	FILE *file = fopen(path.c_str(), "rb");
	if (!file) {
		if (error)
			*error = "cannot open schema file: " + path;
		return false;
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		if (error)
			*error = "cannot seek schema file: " + path;
		return false;
	}
	long size = ftell(file);
	if (size < 0) {
		fclose(file);
		if (error)
			*error = "cannot size schema file: " + path;
		return false;
	}
	rewind(file);
	out->resize((size_t)size);
	size_t read = size ? fread(&(*out)[0], 1, (size_t)size, file) : 0;
	fclose(file);
	if (read != (size_t)size) {
		if (error)
			*error = "cannot read schema file: " + path;
		return false;
	}
	return true;
}

#if HAVE_BSON
static bool is_all_digits(const char *text)
{
	if (!text || !*text)
		return false;
	for (const char *p = text; *p; ++p) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return true;
}

bool load_audit_schema_file(const std::string &path, audit_schema *schema, std::string *error)
{
	if (!schema)
		return false;

	std::string json;
	if (!read_file_to_string(path, &json, error))
		return false;

	bson_error_t bson_error;
	bson_t *doc = bson_new_from_json((const uint8_t *)json.data(), (ssize_t)json.size(), &bson_error);
	if (!doc) {
		if (error)
			*error = std::string("invalid schema JSON: ") + bson_error.message;
		return false;
	}

	bool ok = false;
	// (numeric key, key string, full field name) collected then sorted by numeric key.
	std::vector<std::pair<long, std::pair<std::string, std::string>>> entries;
	do {
		bson_iter_t iter;
		if (!bson_iter_init_find(&iter, doc, "version") || !BSON_ITER_HOLDS_INT32(&iter)) {
			if (error)
				*error = "schema missing integer 'version'";
			break;
		}
		schema->version = bson_iter_int32(&iter);
		if (schema->version <= 0) {
			if (error)
				*error = "schema 'version' must be > 0";
			break;
		}

		if (!bson_iter_init_find(&iter, doc, "fields") || !BSON_ITER_HOLDS_DOCUMENT(&iter)) {
			if (error)
				*error = "schema missing 'fields' object";
			break;
		}

		bson_iter_t field_iter;
		bson_iter_recurse(&iter, &field_iter);
		bool bad = false;
		while (bson_iter_next(&field_iter)) {
			const char *key = bson_iter_key(&field_iter);
			if (!is_all_digits(key)) {
				if (error)
					*error = std::string("schema field key '") + key + "' must be a non-negative integer";
				bad = true;
				break;
			}
			if (!BSON_ITER_HOLDS_UTF8(&field_iter)) {
				if (error)
					*error = std::string("schema field '") + key + "' value must be a string";
				bad = true;
				break;
			}
			uint32_t len = 0;
			const char *full = bson_iter_utf8(&field_iter, &len);
			if (!full || len == 0) {
				if (error)
					*error = std::string("schema field '") + key + "' has an empty name";
				bad = true;
				break;
			}
			entries.push_back({strtol(key, nullptr, 10), {std::string(key), std::string(full, len)}});
		}
		if (bad)
			break;
		if (entries.empty()) {
			if (error)
				*error = "schema 'fields' is empty";
			break;
		}

		std::sort(entries.begin(), entries.end(),
			  [](const auto &a, const auto &b) { return a.first < b.first; });
		for (size_t i = 1; i < entries.size(); ++i) {
			if (entries[i].first == entries[i - 1].first) {
				if (error)
					*error = "duplicate numeric key '" + entries[i].second.first + "' in schema";
				bad = true;
				break;
			}
		}
		if (bad)
			break;
		for (size_t i = 0; i < entries.size() && !bad; ++i) {
			for (size_t j = i + 1; j < entries.size(); ++j) {
				if (entries[i].second.second == entries[j].second.second) {
					if (error)
						*error = "duplicate field name '" + entries[i].second.second + "' in schema";
					bad = true;
					break;
				}
			}
		}
		if (bad)
			break;

		schema->fields.clear();
		schema->fields.reserve(entries.size());
		for (const auto &entry : entries)
			schema->fields.push_back(entry.second);
		ok = true;
	} while (false);

	bson_destroy(doc);
	return ok;
}
#else
bool load_audit_schema_file(const std::string &, audit_schema *, std::string *error)
{
	if (error)
		*error = "libbson headers are not available; cannot parse schema file";
	return false;
}
#endif
