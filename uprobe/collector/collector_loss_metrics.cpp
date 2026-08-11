// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_loss_metrics.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

struct collector_loss_stats {
	std::string collector_id;
	std::string listen_addr;
	unsigned long long accepted_records = 0;
	unsigned long long persisted_records = 0;
	unsigned long long db_queue_dropped_records = 0;
	unsigned long long db_retry_exhausted_records = 0;
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

void collector_loss_metrics_persisted(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.persisted_records += records;
}

void collector_loss_metrics_db_queue_dropped(unsigned long long records)
{
	std::lock_guard<std::mutex> guard(g_loss_stats.mutex);
	g_loss_stats.db_queue_dropped_records += records;
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
	collector_loss_log("event=collector_loss_metrics collector_id=%s listen=%s collector_accepted_records=%llu collector_persisted_records=%llu collector_db_queue_dropped_records=%llu collector_db_retry_exhausted_records=%llu\n",
			   g_loss_stats.collector_id.c_str(), g_loss_stats.listen_addr.c_str(),
			   g_loss_stats.accepted_records,
			   g_loss_stats.persisted_records,
			   g_loss_stats.db_queue_dropped_records,
			   g_loss_stats.db_retry_exhausted_records);
}
