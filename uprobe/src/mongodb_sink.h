// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef MONGODB_SINK_H
#define MONGODB_SINK_H

#include <string>
#include <vector>

#include "audit_event_parser.h"

struct mongodb_config {
	std::string uri = "mongodb://7.27.43.139:27017";
	std::string database = "ob_audit";
	std::string collection = "audit_events";
	std::string app_name = "ebpf-ob-audit-collector";
	std::string write_concern = "w1";
	unsigned int connect_timeout_ms = 2000;
	unsigned int server_selection_timeout_ms = 3000;
	unsigned int socket_timeout_ms = 5000;
	unsigned int pool_min_size = 1;
	unsigned int pool_max_size = 4;
	unsigned int insert_concurrency = 2;
	unsigned int bulk_max_records = 1000;
	unsigned int bulk_max_bytes = 4 * 1024 * 1024;
	bool ordered_insert = false;
};

class MongoSink {
public:
	MongoSink();
	~MongoSink();

	MongoSink(const MongoSink &) = delete;
	MongoSink &operator=(const MongoSink &) = delete;

	bool start(const mongodb_config &config, std::string *error);
	void stop();
	bool enabled() const;
	bool insert_events(const std::string &agent_id, const std::string &server_ip,
			   const std::vector<audit_ingest::parsed_audit_event> &events,
			   unsigned long long *accepted_records, unsigned long long *accepted_bytes,
			   std::string *error);

private:
	struct Impl;
	Impl *impl_;
};

#endif /* MONGODB_SINK_H */
