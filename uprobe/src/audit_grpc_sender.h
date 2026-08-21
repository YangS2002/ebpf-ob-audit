// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_GRPC_SENDER_H
#define AUDIT_GRPC_SENDER_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "audit_accounting.h"
#include "collector_resolver.h"

#ifndef AUDIT_GRPC_TIMING_ENABLED
#define AUDIT_GRPC_TIMING_ENABLED 0
#endif

struct audit_grpc_config {
	std::string agent_id;
	std::string server_ip;
	std::string collector_addr;
	uint32_t file_version = 0;
	uint32_t event_size = 0;
	uint32_t batch_bytes = 0;
	uint32_t flush_interval_ms = 0;
	uint32_t timeout_ms = 0;
	uint64_t pool_bytes = 0;
	uint32_t upload_concurrency = 0;
	uint32_t max_retries = 0;
	uint32_t retry_initial_ms = 0;
	uint32_t retry_max_ms = 0;
	uint32_t keepalive_time_ms = 0;
	uint32_t keepalive_timeout_ms = 0;
	bool keepalive_permit_without_calls = true;
};

struct audit_grpc_stats {
	uint64_t queued_records = 0;
	uint64_t queued_bytes = 0;
	uint64_t accepted_records = 0;
	uint64_t sent_batches = 0;
	uint64_t sent_records = 0;
	uint64_t acknowledged_records = 0;
	uint64_t sent_bytes = 0;
	uint64_t dropped_records = 0;
	uint64_t dropped_bytes = 0;
	uint64_t dropped_no_batch_records = 0;
	uint64_t dropped_no_batch_bytes = 0;
	uint64_t dropped_oversize_records = 0;
	uint64_t dropped_oversize_bytes = 0;
	uint64_t retry_uploads = 0;
	uint64_t dropped_after_retries_batches = 0;
	uint64_t dropped_after_retries_records = 0;
	uint64_t dropped_after_retries_bytes = 0;
	uint32_t active_workers = 0;
	uint32_t max_active_workers = 0;
	uint32_t pool_total_batches = 0;
	uint32_t pool_free_batches = 0;
	uint32_t ready_batches = 0;
	uint32_t max_ready_batches = 0;
	uint64_t failed_uploads = 0;
	uint64_t collector_rejected_records = 0;
	uint64_t collector_queue_full_records = 0;
	uint64_t failed_records = 0;
	uint64_t failed_bytes = 0;
#if AUDIT_GRPC_TIMING_ENABLED
	uint64_t submit_calls = 0;
	uint64_t total_submit_ns = 0;
	uint64_t max_submit_ns = 0;
	uint64_t last_grpc_roundtrip_ns = 0;
	uint64_t max_grpc_roundtrip_ns = 0;
	uint64_t total_grpc_roundtrip_ns = 0;
	uint64_t median_grpc_roundtrip_ns = 0;
#endif
	uint64_t stub_rebuilds = 0;
	uint64_t channel_switches = 0;
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
	bool flush();
	bool submit(char *data, size_t size);
	// 快路径：直接从源缓冲(内核 ringbuf)拷入发送批次，避免调用方中间栈缓冲；
	// 拷入后在批次内就地回填 server_ip（server_ip_off 为 event 内偏移）。
	bool submit(const char *data, size_t size, const char *server_ip,
		    size_t server_ip_off, size_t server_ip_len);
	bool report_metrics(const audit_agent_accounting_snapshot &snapshot);
	bool enabled() const;
	std::string current_collector() const;
	bool wait_ready(uint32_t timeout_ms) const;
	audit_grpc_stats stats() const;

	struct Impl;

private:
	std::unique_ptr<Impl> impl_;
};

#endif /* AUDIT_GRPC_SENDER_H */
