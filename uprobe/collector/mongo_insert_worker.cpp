// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "mongo_insert_worker.h"

#include <chrono>
#include <thread>
#include <utility>

#include "bounded_mpmc_queue.h"
#include "uprobe.h"

MongoInsertTask::MongoInsertTask(std::string agent_id, std::string server_ip, std::string records,
					 std::vector<audit_ingest::parsed_audit_event> events,
					 unsigned long long parse_ns,
					 unsigned long long upload_total_ns)
	: agent_id_(std::move(agent_id)), server_ip_(std::move(server_ip)), records_(std::move(records)), events_(std::move(events)),
	  parse_ns_(parse_ns), upload_total_ns_(upload_total_ns)
{
	for (auto &event : events_)
		event.record = reinterpret_cast<const struct event *>(records_.data() + event.offset);
}

void MongoInsertTask::complete(mongo_insert_result result)
{
	{
		std::lock_guard<std::mutex> lock(mutex_);
		result_ = std::move(result);
		done_ = true;
	}
	cv_.notify_one();
}

mongo_insert_result MongoInsertTask::wait()
{
	std::unique_lock<std::mutex> lock(mutex_);
	cv_.wait(lock, [this] { return done_; });
	return result_;
}

struct MongoInsertWorkerPool::Impl {
	Impl(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity,
	     mongo_insert_complete_cb complete_cb, mongo_insert_attempt_cb attempt_cb)
		: sink(sink), worker_count(worker_count ? worker_count : 1), queue(queue_capacity ? queue_capacity : 1),
		  complete_cb(std::move(complete_cb)), attempt_cb(std::move(attempt_cb))
	{
	}

	MongoSink *sink = nullptr;
	std::size_t worker_count = 1;
	BoundedMpmcQueue<std::shared_ptr<MongoInsertTask>> queue;
	std::vector<std::thread> workers;
	std::mutex mutex;
	mongo_insert_complete_cb complete_cb;
	mongo_insert_attempt_cb attempt_cb;
	bool started = false;
};

MongoInsertWorkerPool::MongoInsertWorkerPool(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity,
					       mongo_insert_complete_cb complete_cb,
					       mongo_insert_attempt_cb attempt_cb)
	: impl_(new Impl(sink, worker_count, queue_capacity, std::move(complete_cb), std::move(attempt_cb)))
{
}

MongoInsertWorkerPool::~MongoInsertWorkerPool()
{
	stop();
}

bool MongoInsertWorkerPool::start()
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	if (impl_->started)
		return true;
	if (!impl_->attempt_cb && (!impl_->sink || !impl_->sink->enabled()))
		return false;
	impl_->started = true;
	impl_->workers.reserve(impl_->worker_count);
	for (std::size_t i = 0; i < impl_->worker_count; i++)
		impl_->workers.emplace_back([this] { worker_loop(); });
	return true;
}

void MongoInsertWorkerPool::stop()
{
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->started)
			return;
		impl_->started = false;
	}
	impl_->queue.close();
	for (auto &worker : impl_->workers) {
		if (worker.joinable())
			worker.join();
	}
	impl_->workers.clear();
}

bool MongoInsertWorkerPool::submit(const std::shared_ptr<MongoInsertTask> &task)
{
	if (!task)
		return false;
	return impl_->queue.try_push(task);
}

void MongoInsertWorkerPool::worker_loop()
{
	std::shared_ptr<MongoInsertTask> task;
		while (impl_->queue.pop(&task)) {
			mongo_insert_result result;
			for (unsigned int attempt = 0; attempt < 4; attempt++) {
				result = mongo_insert_result();
				if (impl_->attempt_cb) {
					result = impl_->attempt_cb(*task, attempt);
				} else if (!impl_->sink || !impl_->sink->enabled()) {
					result.ok = false;
					result.error = "MongoDB sink is not started";
				} else {
		#if AUDIT_GRPC_TIMING_ENABLED
					result.ok = impl_->sink->insert_events(task->agent_id(), task->server_ip(), task->events(),
								   &result.accepted_records, &result.accepted_bytes,
								   &result.error, &result.stats);
		#else
					result.ok = impl_->sink->insert_events(task->agent_id(), task->server_ip(), task->events(),
								   &result.accepted_records, &result.accepted_bytes,
								   &result.error);
		#endif
				}
				if (result.ok)
					break;
				if (attempt < 3)
					std::this_thread::sleep_for(std::chrono::milliseconds(100U << attempt));
			}
		if (impl_->complete_cb)
			impl_->complete_cb(*task, result);
		task->complete(std::move(result));
	}
}
