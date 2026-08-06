// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef MONGO_INSERT_WORKER_H
#define MONGO_INSERT_WORKER_H

#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "audit_event_parser.h"
#include "mongodb_sink.h"

struct mongo_insert_result {
	bool ok = false;
	unsigned long long accepted_records = 0;
	unsigned long long accepted_bytes = 0;
	std::string error;
#if AUDIT_GRPC_TIMING_ENABLED
	mongodb_insert_stats stats;
#endif
};

class MongoInsertTask {
public:
	MongoInsertTask(std::string agent_id, std::string server_ip, std::string records,
			std::vector<audit_ingest::parsed_audit_event> events);

	MongoInsertTask(const MongoInsertTask &) = delete;
	MongoInsertTask &operator=(const MongoInsertTask &) = delete;

	const std::string &agent_id() const { return agent_id_; }
	const std::string &server_ip() const { return server_ip_; }
	const std::vector<audit_ingest::parsed_audit_event> &events() const { return events_; }

	void complete(mongo_insert_result result);
	mongo_insert_result wait();

private:
	std::string agent_id_;
	std::string server_ip_;
	std::string records_;
	std::vector<audit_ingest::parsed_audit_event> events_;
	std::mutex mutex_;
	std::condition_variable cv_;
	bool done_ = false;
	mongo_insert_result result_;
};

class MongoInsertWorkerPool {
public:
	MongoInsertWorkerPool(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity);
	~MongoInsertWorkerPool();

	MongoInsertWorkerPool(const MongoInsertWorkerPool &) = delete;
	MongoInsertWorkerPool &operator=(const MongoInsertWorkerPool &) = delete;

	bool start();
	void stop();
	bool submit(const std::shared_ptr<MongoInsertTask> &task);

private:
	void worker_loop();

	struct Impl;
	std::unique_ptr<Impl> impl_;
};

#endif /* MONGO_INSERT_WORKER_H */
