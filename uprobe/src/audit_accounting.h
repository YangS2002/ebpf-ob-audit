// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_ACCOUNTING_H
#define AUDIT_ACCOUNTING_H

#include <cstdint>
#include <string>

struct audit_agent_accounting_snapshot {
	std::string source_id;
	std::string server_ip;
	uint64_t process_start_unix_ms = 0;
	uint64_t sequence = 0;
	uint64_t report_unix_ms = 0;
	uint64_t ob_audit_seen_records = 0;
	uint64_t ringbuf_lost_records = 0;
	uint64_t agent_received_records = 0;
	uint64_t pending_lost_records = 0;
	uint64_t send_enqueue_lost_records = 0;
	uint64_t collector_rejected_records = 0;
	uint64_t collector_queue_full_records = 0;
	uint64_t upload_retry_exhausted_records = 0;
	uint64_t agent_lost_records = 0;
	uint64_t delivered_records = 0;
	uint64_t acknowledged_records = 0;
	uint64_t inflight_records = 0;
};

struct audit_collector_accounting_snapshot {
	std::string source_id;
	std::string listen_addr;
	uint64_t process_start_unix_ms = 0;
	uint64_t sequence = 0;
	uint64_t report_unix_ms = 0;
	uint64_t accepted_records = 0;
	uint64_t rejected_records = 0;
	uint64_t persisted_records = 0;
	uint64_t db_failed_lost_records = 0;
	uint64_t inflight_records = 0;
};

#endif /* AUDIT_ACCOUNTING_H */
