// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "mongo_insert_worker.h"

#include <utility>

#include "bounded_mpmc_queue.h"
#include "uprobe.h"

MongoInsertTask::MongoInsertTask(std::string agent_id, std::string server_ip, std::string records,
				 std::vector<audit_ingest::parsed_audit_event> events)
	: agent_id_(std::move(agent_id)), server_ip_(std::move(server_ip)), records_(std::move(records)), events_(std::move(events))
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
	Impl(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity)
		: sink(sink), worker_count(worker_count ? worker_count : 1), queue(queue_capacity ? queue_capacity : 1)
	{
	}

	MongoSink *sink = nullptr;
	std::size_t worker_count = 1;
	BoundedMpmcQueue<std::shared_ptr<MongoInsertTask>> queue;
	std::vector<std::thread> workers;
	std::mutex mutex;
	bool started = false;
};

MongoInsertWorkerPool::MongoInsertWorkerPool(MongoSink *sink, std::size_t worker_count, std::size_t queue_capacity)
	: impl_(new Impl(sink, worker_count, queue_capacity))
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
	if (!impl_->sink || !impl_->sink->enabled())
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
	return impl_->queue.push(task);
}

void MongoInsertWorkerPool::worker_loop()
{
	std::shared_ptr<MongoInsertTask> task;
	while (impl_->queue.pop(&task)) {
		mongo_insert_result result;
		if (!impl_->sink || !impl_->sink->enabled()) {
			result.ok = false;
			result.error = "MongoDB sink is not started";
			task->complete(std::move(result));
			continue;
		}
#if AUDIT_GRPC_TIMING_ENABLED
			result.ok = impl_->sink->insert_events(task->agent_id(), task->server_ip(), task->events(),
							   &result.accepted_records, &result.accepted_bytes,
							   &result.error, &result.stats);
#else
			result.ok = impl_->sink->insert_events(task->agent_id(), task->server_ip(), task->events(),
							   &result.accepted_records, &result.accepted_bytes,
							   &result.error);
#endif
		task->complete(std::move(result));
	}
}
