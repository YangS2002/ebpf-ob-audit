// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_event_parser.h"

#include <cstring>

namespace audit_ingest {

static const unsigned int AUDIT_RECORD_MAX =
	(unsigned int)sizeof(event) + AUDIT_SQL_CAPTURE_MAX + AUDIT_PARAMS_CAPTURE_MAX;

static bool variable_event_valid(const event *e, unsigned int total_size)
{
	if (e->record_type != AUDIT_RECORD_EVENT)
		return false;
	if (total_size < event_payload_offset())
		return false;
	if (total_size > AUDIT_RECORD_MAX)
		return false;
	return event_payload_offset() + event_payload_len(e) == total_size;
}

bool parse_audit_records(const char *data, std::size_t size,
			 std::vector<parsed_audit_event> *events, std::string *error)
{
	if (!events)
		return false;
	events->clear();
	if (!data && size != 0) {
		if (error)
			*error = "records data is null";
		return false;
	}

	std::size_t offset = 0;
	while (offset < size) {
		if (size - offset < sizeof(unsigned int)) {
			if (error)
				*error = "truncated record header";
			return false;
		}

		unsigned int total_size = 0;
		memcpy(&total_size, data + offset, sizeof(total_size));
		if (total_size < event_payload_offset() || total_size > AUDIT_RECORD_MAX) {
			if (error)
				*error = "invalid record total_size";
			return false;
		}
		if (total_size > size - offset) {
			if (error)
				*error = "record exceeds batch boundary";
			return false;
		}

		const event *record = reinterpret_cast<const event *>(data + offset);
		if (!variable_event_valid(record, total_size)) {
			if (error)
				*error = "invalid compact audit event";
			return false;
		}

		events->push_back({record, offset, total_size});
		offset += total_size;
	}
	return true;
}

}
