// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_TIMING_H
#define COLLECTOR_TIMING_H

#include <string>

#include "mongodb_sink.h"

#if AUDIT_PERF_FIELDS_ENABLED || AUDIT_GRPC_TIMING_ENABLED
unsigned long long collector_timing_now_ns();
#endif

#if AUDIT_GRPC_TIMING_ENABLED
void collector_timing_log_enabled(const std::string &collector_id, const std::string &listen_addr,
					  const std::string &storage, const char *config_path);
void record_collector_timing(const std::string &collector_id, const std::string &listen_addr,
			     unsigned long long records, unsigned long long bytes,
			     unsigned long long parse_ns,
			     const mongodb_insert_stats &insert_stats,
			     unsigned long long upload_total_ns);
#define COLLECTOR_TIMING_NOW() collector_timing_now_ns()
#else
#define COLLECTOR_TIMING_NOW() 0ULL
#endif

#endif /* COLLECTOR_TIMING_H */
