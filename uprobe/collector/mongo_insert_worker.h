// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef MONGO_INSERT_WORKER_H
#define MONGO_INSERT_WORKER_H

#include <condition_variable>
#include <functional>
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

class MongoInsertTask;
using mongo_insert_complete_cb = std::function<void(const MongoInsertTask &, const mongo_insert_result &)>;
using mongo_insert_attempt_cb = std::function<mongo_insert_result(const MongoInsertTask &, unsigned int)>;

class MongoInsertTask {
public:
	MongoInsertTask(std::string agent_id, std::string server_ip, std::string records,
			std::vector<audit_ingest::parsed_audit_event> events,
			unsigned long long parse_ns = 0,
			unsigned long long upload_total_ns = 0);

	MongoInsertTask(const MongoInsertTask &) = delete;
	MongoInsertTask &operator=(const MongoInsertTask &) = delete;

	const std::string &agent_id() const { return agent_id_; }
	const std::string &server_ip() const { return server_ip_; }
	const std::vector<audit_ingest::parsed_audit_event> &events() const { return events_; }
	unsigned long long records_size() const { return records_.size(); }
	unsigned long long parse_ns() const { return parse_ns_; }
	unsigned long long upload_total_ns() const { return upload_total_ns_; }
	void set_upload_total_ns(unsigned long long upload_total_ns) { upload_total_ns_ = upload_total_ns; }

	void complete(mongo_insert_result result);
	mongo_insert_result wait();

private:
	std::string agent_id_;
	std::string server_ip_;
	std::string records_;
	std::vector<audit_ingest::parsed_audit_event> events_;
	unsigned long long parse_ns_ = 0;
	unsigned long long upload_total_ns_ = 0;
	std::mutex mutex_;
	std::condition_variable cv_;
	bool done_ = false;
	mongo_insert_result result_;
};

class MongoInsertWorkerPool {
public:
	MongoInsertWorkerPool(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity,
			      mongo_insert_complete_cb complete_cb = mongo_insert_complete_cb(),
			      mongo_insert_attempt_cb attempt_cb = mongo_insert_attempt_cb());
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
