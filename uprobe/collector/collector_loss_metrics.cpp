// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_loss_metrics.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

static unsigned long long wall_time_ms()
{
	return (unsigned long long)time(nullptr) * 1000ULL;
}

struct collector_loss_stats {
	std::string collector_id;
	std::string listen_addr;
	unsigned long long accepted_records = 0;
	unsigned long long rejected_records = 0;
	unsigned long long persisted_records = 0;
	unsigned long long db_retry_exhausted_records = 0;
	unsigned long long process_start_unix_ms = wall_time_ms();
	unsigned long long sequence = 0;
	unsigned long long last_log_sec = 0;
	std::mutex mutex;
};

static collector_loss_stats g_loss_stats;

static unsigned long long now_sec()
{
	return (unsigned long long)time(nullptr);
}

static void collector_loss_log(const char *fmt, ...)
{
	FILE *file = fopen("logs/collector_loss_metrics.log", "a");
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

void collector_loss_metrics_init(const std::string &collector_id, const std::string &listen_addr)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.collector_id = collector_id;
	g_loss_stats.listen_addr = listen_addr;
	collector_loss_log("event=collector_loss_metrics_enabled collector_id=%s listen=%s\n",
			   collector_id.c_str(), listen_addr.c_str());
}

void collector_loss_metrics_accepted(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.accepted_records += records;
}

void collector_loss_metrics_rejected(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.rejected_records += records;
}

void collector_loss_metrics_persisted(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.persisted_records += records;
}

void collector_loss_metrics_db_retry_exhausted(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.db_retry_exhausted_records += records;
}

void collector_loss_metrics_flush()
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	unsigned long long now = now_sec();
	if (g_loss_stats.last_log_sec != 0 && now == g_loss_stats.last_log_sec)
		return;
	g_loss_stats.last_log_sec = now;
	unsigned long long inflight = g_loss_stats.accepted_records - g_loss_stats.persisted_records - g_loss_stats.db_retry_exhausted_records;
	collector_loss_log("event=collector_audit_accounting collector_id=%s listen=%s accepted_records=%llu rejected_records=%llu persisted_records=%llu db_failed_lost_records=%llu inflight_records=%llu\n",
			   g_loss_stats.collector_id.c_str(), g_loss_stats.listen_addr.c_str(),
			   g_loss_stats.accepted_records,
			   g_loss_stats.rejected_records,
			   g_loss_stats.persisted_records,
			   g_loss_stats.db_retry_exhausted_records,
			   inflight);
}

audit_collector_accounting_snapshot collector_loss_metrics_snapshot()
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	audit_collector_accounting_snapshot snapshot;
	snapshot.source_id = g_loss_stats.collector_id;
	snapshot.listen_addr = g_loss_stats.listen_addr;
	snapshot.process_start_unix_ms = g_loss_stats.process_start_unix_ms;
	snapshot.sequence = ++g_loss_stats.sequence;
	snapshot.report_unix_ms = wall_time_ms();
	snapshot.accepted_records = g_loss_stats.accepted_records;
	snapshot.rejected_records = g_loss_stats.rejected_records;
	snapshot.persisted_records = g_loss_stats.persisted_records;
	snapshot.db_failed_lost_records = g_loss_stats.db_retry_exhausted_records;
	snapshot.inflight_records = g_loss_stats.accepted_records - g_loss_stats.persisted_records - g_loss_stats.db_retry_exhausted_records;
	return snapshot;
}
