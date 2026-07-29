// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_EVENT_PARSER_H
#define AUDIT_EVENT_PARSER_H

#include <cstddef>
#include <string>
#include <vector>

#include "uprobe.h"

namespace audit_ingest {

struct parsed_audit_event {
	const event *record = nullptr;
	std::size_t offset = 0;
	std::size_t size = 0;
};

bool parse_audit_records(const char *data, std::size_t size,
			 std::vector<parsed_audit_event> *events, std::string *error);

}

#endif /* AUDIT_EVENT_PARSER_H */
