// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_timing.h"

#if AUDIT_PERF_FIELDS_ENABLED || AUDIT_GRPC_TIMING_ENABLED

#include <chrono>

unsigned long long collector_timing_now_ns()
{
	return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

#endif

#if AUDIT_GRPC_TIMING_ENABLED

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

static double ns_to_us(unsigned long long ns)
{
	return (double)ns / 1000.0;
}

static void audit_timing_log(const char *fmt, ...)
{
	FILE *file = fopen("logs/collector_timing.log", "a");
	if (!file)
		return;
	time_t now = time(nullptr);
	tm tm_now = {};
	localtime_r(&now, &tm_now);
	char ts[32];
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm_now);
	fprintf(file, "ts=%s ", ts);
	va_list args;
	va_start(args, fmt);
	vfprintf(file, fmt, args);
	va_end(args);
	fclose(file);
}

struct collector_timing_stats {
	unsigned long long batches = 0;
	unsigned long long records = 0;
	unsigned long long bytes = 0;
	unsigned long long parse_ns = 0;
	unsigned long long build_docs_ns = 0;
	unsigned long long insert_many_ns = 0;
	unsigned long long mongo_total_ns = 0;
	unsigned long long upload_total_ns = 0;
	unsigned long long max_upload_total_ns = 0;
	unsigned long long max_insert_many_ns = 0;
	unsigned long long last_log_ns = 0;
	std::mutex mutex;
};

static collector_timing_stats g_timing_stats;

void collector_timing_log_enabled(const std::string &collector_id, const std::string &listen_addr,
					  const std::string &storage, const char *config_path)
{
	audit_timing_log("event=collector_timing_enabled collector_id=%s listen=%s storage=%s config=%s\n",
			 collector_id.c_str(), listen_addr.c_str(), storage.c_str(), config_path);
}

void record_collector_timing(const std::string &collector_id, const std::string &listen_addr,
			     unsigned long long records, unsigned long long bytes,
			     unsigned long long parse_ns,
			     const mongodb_insert_stats &insert_stats,
			     unsigned long long upload_total_ns)
{
	std::lock_guard<std::mutex> guard(g_timing_stats.mutex);
	g_timing_stats.batches++;
	g_timing_stats.records += records;
	g_timing_stats.bytes += bytes;
	g_timing_stats.parse_ns += parse_ns;
	g_timing_stats.build_docs_ns += insert_stats.build_docs_ns;
	g_timing_stats.insert_many_ns += insert_stats.insert_many_ns;
	g_timing_stats.mongo_total_ns += insert_stats.total_ns;
	g_timing_stats.upload_total_ns += upload_total_ns;
	if (upload_total_ns > g_timing_stats.max_upload_total_ns)
		g_timing_stats.max_upload_total_ns = upload_total_ns;
	if (insert_stats.insert_many_ns > g_timing_stats.max_insert_many_ns)
		g_timing_stats.max_insert_many_ns = insert_stats.insert_many_ns;

	const unsigned long long now_ns = collector_timing_now_ns();
	if (g_timing_stats.last_log_ns != 0 && now_ns - g_timing_stats.last_log_ns < 1000000000ULL)
		return;
	g_timing_stats.last_log_ns = now_ns;

	audit_timing_log(
		"event=collector_metrics collector_id=%s listen=%s batches=%llu records=%llu bytes=%llu avg_records=%.3f avg_bytes=%.3f avg_parse_us=%.3f avg_build_docs_us=%.3f avg_insert_many_us=%.3f avg_mongo_total_us=%.3f avg_upload_total_us=%.3f max_insert_many_us=%.3f max_upload_total_us=%.3f\n",
		collector_id.c_str(), listen_addr.c_str(),
		g_timing_stats.batches, g_timing_stats.records, g_timing_stats.bytes,
		(double)g_timing_stats.records / (double)g_timing_stats.batches,
		(double)g_timing_stats.bytes / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.parse_ns) / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.build_docs_ns) / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.insert_many_ns) / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.mongo_total_ns) / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.upload_total_ns) / (double)g_timing_stats.batches,
		ns_to_us(g_timing_stats.max_insert_many_ns),
		ns_to_us(g_timing_stats.max_upload_total_ns));
}

#endif
