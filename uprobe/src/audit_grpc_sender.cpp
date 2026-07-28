// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_grpc_sender.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"

struct AuditGrpcSender::Impl {
	bool enabled = false;
	bool stopping = false;
	bool started = false;
	audit_grpc_config config;
	audit_grpc_stats stats;
	std::unique_ptr<CollectorResolver> resolver;
	std::string current_addr;
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<audit::AuditCollector::Stub> stub;
	std::thread worker;
	mutable std::mutex mutex;
	std::condition_variable cond;
	std::deque<std::vector<char>> queue;
	uint64_t queued_bytes = 0;
	std::vector<char> batch;
	uint64_t batch_records = 0;
};

static uint32_t default_or(uint32_t value, uint32_t default_value)
{
	return value ? value : default_value;
}

static uint64_t default_or64(uint64_t value, uint64_t default_value)
{
	return value ? value : default_value;
}

AuditGrpcSender::AuditGrpcSender() : impl_(new Impl)
{
}

AuditGrpcSender::~AuditGrpcSender()
{
	stop();
}

static bool connect_current_collector(AuditGrpcSender::Impl *impl)
{
	if (!impl->resolver)
		return false;
	std::string addr = impl->resolver->current();
	if (addr.empty())
		return false;
	impl->current_addr = addr;
	impl->channel = grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
	impl->stub = audit::AuditCollector::NewStub(impl->channel);
	return true;
}

static bool switch_collector(AuditGrpcSender::Impl *impl)
{
	if (!impl->resolver)
		return false;
	if (!impl->current_addr.empty())
		impl->resolver->report_failure(impl->current_addr);
	std::string addr = impl->resolver->next();
	if (addr.empty())
		return false;
	impl->current_addr = addr;
	impl->channel = grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
	impl->stub = audit::AuditCollector::NewStub(impl->channel);
	fprintf(stderr, "grpc switch collector: %s\n", addr.c_str());
	return true;
}

static bool upload_batch(AuditGrpcSender::Impl *impl)
{
	if (!impl->enabled || impl->batch.empty())
		return true;
	if (!impl->stub && !connect_current_collector(impl))
		return false;

	audit::AuditBatch batch;
	batch.set_agent_id(impl->config.agent_id);
	batch.set_server_ip(impl->config.server_ip);
	batch.set_file_version(impl->config.file_version);
	batch.set_event_size(impl->config.event_size);
	batch.set_record_count(impl->batch_records);
	batch.set_records(impl->batch.data(), impl->batch.size());

	audit::UploadReply reply;
	grpc::ClientContext context;
	if (impl->config.timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() +
				     std::chrono::milliseconds(impl->config.timeout_ms));
	grpc::Status status = impl->stub->Upload(&context, batch, &reply);
	if (!status.ok() || !reply.ok()) {
		fprintf(stderr, "grpc upload failed: collector=%s %s %s\n", impl->current_addr.c_str(),
			status.error_message().c_str(), reply.message().c_str());
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.failed_uploads++;
		}
		switch_collector(impl);
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->stats.sent_batches++;
		impl->stats.sent_records += impl->batch_records;
		impl->stats.sent_bytes += impl->batch.size();
	}
	impl->batch.clear();
	impl->batch_records = 0;
	return true;
}

static void flush_with_retry(AuditGrpcSender::Impl *impl)
{
	uint32_t delay_ms = impl->config.retry_initial_ms;
	while (true) {
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			if (impl->stopping) {
				impl->batch.clear();
				impl->batch_records = 0;
				return;
			}
		}
		if (upload_batch(impl))
			return;
		std::unique_lock<std::mutex> lock(impl->mutex);
		impl->cond.wait_for(lock, std::chrono::milliseconds(delay_ms), [&] { return impl->stopping; });
		if (impl->stopping)
			return;
		delay_ms = std::min<uint32_t>(delay_ms * 2, impl->config.retry_max_ms);
	}
}

static void sender_worker(AuditGrpcSender::Impl *impl)
{
	while (true) {
		std::vector<char> record;
		{
			std::unique_lock<std::mutex> lock(impl->mutex);
			impl->cond.wait(lock, [&] { return impl->stopping || !impl->queue.empty(); });
			if (impl->queue.empty()) {
				if (impl->stopping)
					break;
				continue;
			}
			record = std::move(impl->queue.front());
			impl->queue.pop_front();
			impl->queued_bytes -= record.size();
			impl->stats.queued_records = impl->queue.size();
			impl->stats.queued_bytes = impl->queued_bytes;
		}

		impl->batch.insert(impl->batch.end(), record.begin(), record.end());
		impl->batch_records++;
		if (impl->config.batch_bytes > 0 && impl->batch.size() >= impl->config.batch_bytes)
			flush_with_retry(impl);
	}
	flush_with_retry(impl);
}

bool AuditGrpcSender::start(const audit_grpc_config &config)
{
	std::unique_ptr<CollectorResolver> resolver(new StaticCollectorResolver(config.collector_addr));
	return start(config, std::move(resolver));
}

bool AuditGrpcSender::start(const audit_grpc_config &config, std::unique_ptr<CollectorResolver> resolver)
{
	stop();
	if (!resolver || !resolver->start())
		return false;

	impl_->config = config;
	impl_->config.agent_id = impl_->config.agent_id.empty() ? "default-agent" : impl_->config.agent_id;
	impl_->config.batch_bytes = default_or(impl_->config.batch_bytes, 262144);
	impl_->config.timeout_ms = default_or(impl_->config.timeout_ms, 2000);
	impl_->config.queue_bytes = default_or64(impl_->config.queue_bytes, 64ULL * 1024 * 1024);
	impl_->config.retry_initial_ms = default_or(impl_->config.retry_initial_ms, 100);
	impl_->config.retry_max_ms = default_or(impl_->config.retry_max_ms, 5000);
	impl_->resolver = std::move(resolver);
	impl_->enabled = true;
	impl_->stopping = false;
	impl_->started = true;
	impl_->worker = std::thread(sender_worker, impl_.get());
	connect_current_collector(impl_.get());
	return true;
}

void AuditGrpcSender::stop()
{
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->started)
			return;
		impl_->stopping = true;
	}
	impl_->cond.notify_all();
	if (impl_->worker.joinable())
		impl_->worker.join();
	impl_->started = false;
	impl_->enabled = false;
	if (impl_->resolver) {
		impl_->resolver->stop();
		impl_->resolver.reset();
	}
	impl_->queue.clear();
	impl_->queued_bytes = 0;
	impl_->batch.clear();
	impl_->batch_records = 0;
}

bool AuditGrpcSender::submit(const char *data, size_t size)
{
	if (!data || size == 0 || !impl_->enabled)
		return false;

	std::lock_guard<std::mutex> lock(impl_->mutex);
	if (impl_->stopping || impl_->queued_bytes + size > impl_->config.queue_bytes) {
		impl_->stats.dropped_records++;
		impl_->stats.dropped_bytes += size;
		return false;
	}
	impl_->queue.emplace_back(data, data + size);
	impl_->queued_bytes += size;
	impl_->stats.queued_records = impl_->queue.size();
	impl_->stats.queued_bytes = impl_->queued_bytes;
	impl_->cond.notify_one();
	return true;
}

bool AuditGrpcSender::enabled() const
{
	return impl_->enabled;
}

std::string AuditGrpcSender::current_collector() const
{
	return impl_->current_addr;
}

bool AuditGrpcSender::wait_ready(uint32_t timeout_ms) const
{
	if (!impl_->enabled || !impl_->channel)
		return false;
	return impl_->channel->WaitForConnected(std::chrono::system_clock::now() +
					       std::chrono::milliseconds(timeout_ms));
}

audit_grpc_stats AuditGrpcSender::stats() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->stats;
}
