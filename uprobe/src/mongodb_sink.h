// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef MONGODB_SINK_H
#define MONGODB_SINK_H

#include <cstdint>
#include <string>
#include <vector>

#include "audit_accounting.h"
#include "audit_event_parser.h"

struct mongodb_config {
	std::string uri = "mongodb://7.27.43.139:27017";
	std::string database = "ob_audit";
	std::string collection = "audit_events";
	std::string metrics_collection = "audit_pipeline_metrics";
	std::string schema_collection = "audit_schemas";
	unsigned int event_ttl_days = 3;
	unsigned int metrics_ttl_days = 1;
	std::string schema_file_path = "audit_schema.json";
	std::string app_name = "ebpf-ob-audit-collector";
	std::string write_concern = "w1";
	unsigned int write_concern_wtimeout_ms = 2000;
	unsigned int connect_timeout_ms = 2000;
	unsigned int server_selection_timeout_ms = 3000;
	unsigned int socket_timeout_ms = 5000;
	unsigned int pool_min_size = 1;
	unsigned int pool_max_size = 4;
	unsigned int insert_concurrency = 2;
	unsigned int worker_count = 0;
	unsigned int queue_capacity = 1024;
	unsigned int bulk_max_records = 1000;
	unsigned int bulk_max_bytes = 4 * 1024 * 1024;
	bool ordered_insert = false;
};

#if AUDIT_GRPC_TIMING_ENABLED
struct mongodb_insert_stats {
	uint64_t build_docs_ns = 0;
	uint64_t insert_many_ns = 0;
	uint64_t total_ns = 0;
};
#endif

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
			   std::string *error
#if AUDIT_GRPC_TIMING_ENABLED
			   , mongodb_insert_stats *insert_stats = nullptr
#endif
			   );
	bool insert_agent_metrics(const audit_agent_accounting_snapshot &snapshot, std::string *error);
	bool insert_collector_metrics(const audit_collector_accounting_snapshot &snapshot, std::string *error);

private:
	struct Impl;
	Impl *impl_;
};

#endif /* MONGODB_SINK_H */
