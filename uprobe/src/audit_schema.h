// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_SCHEMA_H
#define AUDIT_SCHEMA_H

#include <string>
#include <utility>
#include <vector>

// Parsed representation of an external audit schema file. The file drives the
// on-disk document shape so the collector code does not hard-code field keys:
//
//   { "version": <int>, "fields": { "<numeric-key>": "<full_field_name>", ... } }
//
// Numeric string keys (assigned in the file) are mechanically unique and avoid
// the collision risk of hand-picked abbreviations. `version` is written into
// every event document as `sv` so downstream readers can fetch the exact schema.
struct audit_schema {
	int version = 0;
	// (numeric key string, full field name), ordered by ascending numeric key.
	std::vector<std::pair<std::string, std::string>> fields;
};

// Load and validate the schema file at `path`. On failure returns false and, if
// `error` is non-null, sets a human-readable message. Validation checks:
//   - top-level integer `version` > 0
//   - `fields` is a non-empty object of numeric-string keys -> non-empty strings
//   - numeric keys and full field names are each unique
bool load_audit_schema_file(const std::string &path, audit_schema *schema, std::string *error);

#endif /* AUDIT_SCHEMA_H */
