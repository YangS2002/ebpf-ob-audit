// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "agent_logger.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>

static FILE *log_file;

static void agent_log_write(const char *level, const char *fmt, va_list args)
{
	FILE *out = log_file ? log_file : stderr;
	time_t now = time(nullptr);
	tm tm_now = {};
	localtime_r(&now, &tm_now);
	char ts[32];
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm_now);
	fprintf(out, "ts=%s level=%s ", ts, level);
	vfprintf(out, fmt, args);
	fprintf(out, "\n");
	fflush(out);
}

bool agent_log_init(const char *path)
{
	if (!path || !*path)
		return false;
	FILE *file = fopen(path, "a");
	if (!file)
		return false;
	if (log_file)
		fclose(log_file);
	log_file = file;
	setvbuf(log_file, nullptr, _IOLBF, 0);
	return true;
}

void agent_log_close()
{
	if (!log_file)
		return;
	fclose(log_file);
	log_file = nullptr;
}

void agent_log_info(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	agent_log_write("INFO", fmt, args);
	va_end(args);
}

void agent_log_error(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	agent_log_write("ERROR", fmt, args);
	va_end(args);
}
