// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_GRPC_SENDER_H
#define AUDIT_GRPC_SENDER_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "collector_resolver.h"

struct audit_grpc_config {
	std::string agent_id;
	std::string server_ip;
	std::string collector_addr;
	uint32_t file_version = 0;
	uint32_t event_size = 0;
	uint32_t batch_bytes = 0;
	uint32_t timeout_ms = 0;
	uint64_t queue_bytes = 0;
	uint32_t retry_initial_ms = 0;
	uint32_t retry_max_ms = 0;
};

struct audit_grpc_stats {
	uint64_t queued_records = 0;
	uint64_t queued_bytes = 0;
	uint64_t sent_batches = 0;
	uint64_t sent_records = 0;
	uint64_t sent_bytes = 0;
	uint64_t dropped_records = 0;
	uint64_t dropped_bytes = 0;
	uint64_t failed_uploads = 0;
};

class AuditGrpcSender {
public:
	AuditGrpcSender();
	~AuditGrpcSender();

	AuditGrpcSender(const AuditGrpcSender &) = delete;
	AuditGrpcSender &operator=(const AuditGrpcSender &) = delete;

	bool start(const audit_grpc_config &config);
	bool start(const audit_grpc_config &config, std::unique_ptr<CollectorResolver> resolver);
	void stop();
	bool submit(const char *data, size_t size);
	bool enabled() const;
	bool wait_ready(uint32_t timeout_ms) const;
	audit_grpc_stats stats() const;

	struct Impl;

private:
	std::unique_ptr<Impl> impl_;
};

#endif /* AUDIT_GRPC_SENDER_H */
