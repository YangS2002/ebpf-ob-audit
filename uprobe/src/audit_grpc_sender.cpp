// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_grpc_sender.h"
#include "uprobe.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"

static constexpr uint32_t DEFAULT_GRPC_BATCH_BYTES = 262144;
static constexpr uint32_t DEFAULT_GRPC_FLUSH_INTERVAL_MS = 1000;
static constexpr uint32_t DEFAULT_GRPC_TIMEOUT_MS = 2000;
static constexpr uint64_t DEFAULT_GRPC_POOL_BYTES = 64ULL * 1024 * 1024;
static constexpr uint32_t DEFAULT_GRPC_UPLOAD_CONCURRENCY = 2;
static constexpr uint32_t DEFAULT_GRPC_MAX_RETRIES = 3;
static constexpr uint32_t DEFAULT_GRPC_RETRY_INITIAL_MS = 100;
static constexpr uint32_t DEFAULT_GRPC_RETRY_MAX_MS = 500;
static constexpr uint32_t MAX_GRPC_UPLOAD_CONCURRENCY = 8;

struct AuditGrpcSender::Impl {
	struct Batch {
		char *data = nullptr;
		uint32_t capacity = 0;
		uint32_t used = 0;
		uint32_t record_count = 0;
		std::chrono::steady_clock::time_point first_record_time;
	};

	struct BatchPool {
		std::unique_ptr<char[]> memory;
		std::unique_ptr<Batch[]> batches;
		std::vector<uint32_t> free_indexes;
		std::vector<bool> free_flags;
		uint32_t batch_count = 0;
		uint32_t batch_bytes = 0;

		bool init(uint64_t pool_bytes, uint32_t batch_size, uint32_t min_batches)
		{
			if (batch_size == 0)
				return false;
			uint64_t count = pool_bytes / batch_size;
			if (count < min_batches || count > UINT32_MAX)
				return false;
			memory.reset(new (std::nothrow) char[count * batch_size]);
			batches.reset(new (std::nothrow) Batch[count]);
			if (!memory || !batches)
				return false;
			free_indexes.clear();
			free_indexes.reserve((size_t)count);
			free_flags.assign((size_t)count, true);
			batch_count = (uint32_t)count;
			batch_bytes = batch_size;
			for (uint32_t i = 0; i < batch_count; i++) {
				batches[i].data = memory.get() + (uint64_t)i * batch_bytes;
				batches[i].capacity = batch_bytes;
				batches[i].used = 0;
				batches[i].record_count = 0;
				free_indexes.push_back(batch_count - 1 - i);
			}
			return true;
		}

		Batch *acquire()
		{
			if (free_indexes.empty())
				return nullptr;
			uint32_t idx = free_indexes.back();
			free_indexes.pop_back();
			free_flags[idx] = false;
			Batch *batch = &batches[idx];
			batch->used = 0;
			batch->record_count = 0;
			batch->first_record_time = std::chrono::steady_clock::time_point();
			return batch;
		}

		void release(Batch *batch)
		{
			if (!batch || !batches)
				return;
			uint32_t idx = (uint32_t)(batch - batches.get());
			if (idx >= batch_count || free_flags[idx])
				return;
			batch->used = 0;
			batch->record_count = 0;
			batch->first_record_time = std::chrono::steady_clock::time_point();
			free_flags[idx] = true;
			free_indexes.push_back(idx);
		}

		uint32_t free_count() const { return (uint32_t)free_indexes.size(); }
	};

	bool enabled = false;
	bool stopping = false;
	bool started = false;
	audit_grpc_config config;
	audit_grpc_stats stats;
	std::unique_ptr<CollectorResolver> resolver;
	std::string current_addr;
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<audit::AuditCollector::Stub> stub;
	std::vector<std::thread> workers;
	mutable std::mutex mutex;
	std::condition_variable cond;
	BatchPool pool;
		Batch *current_batch = nullptr;
		std::deque<Batch *> ready_batches;
		uint64_t queued_records = 0;
		uint64_t queued_bytes = 0;
	};

static uint32_t default_or(uint32_t value, uint32_t default_value)
{
	return value ? value : default_value;
}

static uint64_t default_or64(uint64_t value, uint64_t default_value)
{
	return value ? value : default_value;
}

static uint64_t monotonic_ns()
{
	return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

AuditGrpcSender::AuditGrpcSender() : impl_(new Impl)
{
}

AuditGrpcSender::~AuditGrpcSender()
{
	stop();
}

static void update_pool_stats_locked(AuditGrpcSender::Impl *impl)
{
	impl->stats.queued_records = impl->queued_records;
	impl->stats.queued_bytes = impl->queued_bytes;
	impl->stats.pool_total_batches = impl->pool.batch_count;
	impl->stats.pool_free_batches = impl->pool.free_count();
	impl->stats.ready_batches = (uint32_t)impl->ready_batches.size();
}

static void sub_queued_locked(AuditGrpcSender::Impl *impl, const AuditGrpcSender::Impl::Batch *batch)
{
	impl->queued_records -= batch->record_count;
	impl->queued_bytes -= batch->used;
	update_pool_stats_locked(impl);
}

static void reset_queue_counters_locked(AuditGrpcSender::Impl *impl)
{
	impl->queued_records = 0;
	impl->queued_bytes = 0;
	update_pool_stats_locked(impl);
}

static bool current_batch_expired_locked(AuditGrpcSender::Impl *impl, std::chrono::steady_clock::time_point now)
{
	return impl->current_batch && impl->current_batch->record_count > 0 &&
		impl->config.flush_interval_ms > 0 &&
		now - impl->current_batch->first_record_time >= std::chrono::milliseconds(impl->config.flush_interval_ms);
}

static void seal_current_batch_locked(AuditGrpcSender::Impl *impl)
{
	if (!impl->current_batch || impl->current_batch->record_count == 0)
		return;
	impl->ready_batches.push_back(impl->current_batch);
	impl->current_batch = nullptr;
	update_pool_stats_locked(impl);
	impl->cond.notify_one();
}

static bool connect_current_collector(AuditGrpcSender::Impl *impl)
{
	std::string addr;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (!impl->resolver)
			return false;
		addr = impl->resolver->current();
	}
	if (addr.empty())
		return false;

	auto channel = grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
	auto stub = audit::AuditCollector::NewStub(channel);
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->current_addr = addr;
		impl->channel = std::move(channel);
		impl->stub = std::move(stub);
	}
	return true;
}

static bool switch_collector(AuditGrpcSender::Impl *impl)
{
	std::string failed_addr;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (!impl->resolver)
			return false;
		failed_addr = impl->current_addr;
	}
	if (!failed_addr.empty())
		impl->resolver->report_failure(failed_addr);

	std::string addr = impl->resolver->next();
	if (addr.empty())
		return false;

	auto channel = grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
	auto stub = audit::AuditCollector::NewStub(channel);
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->current_addr = addr;
		impl->channel = std::move(channel);
		impl->stub = std::move(stub);
	}
	fprintf(stderr, "grpc switch collector: %s\n", addr.c_str());
	return true;
}

#if AUDIT_PERF_FIELDS_ENABLED
static std::string db_name_from_records(const char *records, size_t size)
{
	if (size < event_payload_offset())
		return "";
	const event *e = reinterpret_cast<const event *>(records);
	if (!event_compact_size_valid(e))
		return "";
	return std::string(event_db_name(e), e->db_name_len);
}
#endif

static bool upload_once(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::Batch *local_batch)
{
	if (!local_batch || local_batch->used == 0 || local_batch->record_count == 0)
		return true;
	std::string current_addr;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		current_addr = impl->current_addr;
	}
	if (current_addr.empty()) {
		if (!connect_current_collector(impl))
			return false;
		std::lock_guard<std::mutex> lock(impl->mutex);
		current_addr = impl->current_addr;
		if (current_addr.empty())
			return false;
	}
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (!impl->enabled)
			return false;
	}
	auto channel = grpc::CreateChannel(current_addr, grpc::InsecureChannelCredentials());
	auto stub = audit::AuditCollector::NewStub(channel);

	audit::AuditBatch batch;
	batch.set_agent_id(impl->config.agent_id);
	batch.set_server_ip(impl->config.server_ip);
	batch.set_file_version(impl->config.file_version);
	batch.set_event_size(impl->config.event_size);
	batch.set_record_count(local_batch->record_count);
	batch.set_records(local_batch->data, local_batch->used);

	audit::UploadReply reply;
	grpc::ClientContext context;
	if (impl->config.timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() +
				     std::chrono::milliseconds(impl->config.timeout_ms));
	const uint64_t upload_start_ns = monotonic_ns();
	grpc::Status status = stub->Upload(&context, batch, &reply);
	const uint64_t grpc_roundtrip_ns = monotonic_ns() - upload_start_ns;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (impl->current_addr == current_addr && (!status.ok() || !reply.ok()))
			impl->stub.reset();
	}
	if (!status.ok() || !reply.ok()) {
		fprintf(stderr, "grpc upload failed: collector=%s records=%u bytes=%u %s %s\n",
			current_addr.c_str(), local_batch->record_count, local_batch->used,
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
		impl->stats.last_grpc_roundtrip_ns = grpc_roundtrip_ns;
		impl->stats.total_grpc_roundtrip_ns += grpc_roundtrip_ns;
		impl->stats.max_grpc_roundtrip_ns = std::max(impl->stats.max_grpc_roundtrip_ns, grpc_roundtrip_ns);
		impl->stats.sent_batches++;
		impl->stats.sent_records += local_batch->record_count;
		impl->stats.sent_bytes += local_batch->used;
	}
#if AUDIT_PERF_FIELDS_ENABLED
	std::string db_name = db_name_from_records(local_batch->data, local_batch->used);
	fprintf(stderr,
		"grpc upload perf: collector=%s db_name=%s records=%u bytes=%u roundtrip_us=%.3f\n",
		current_addr.c_str(), db_name.c_str(), local_batch->record_count, local_batch->used,
		(double)grpc_roundtrip_ns / 1000.0);
#endif
	return true;
}

static uint32_t retry_delay_ms(const audit_grpc_config &config, uint32_t retry_index)
{
	uint64_t delay = default_or(config.retry_initial_ms, DEFAULT_GRPC_RETRY_INITIAL_MS);
	uint32_t max_delay = default_or(config.retry_max_ms, DEFAULT_GRPC_RETRY_MAX_MS);
	for (uint32_t i = 0; i < retry_index; i++)
		delay = std::min<uint64_t>(delay * 2, max_delay);
	return (uint32_t)std::min<uint64_t>(delay, max_delay);
}

static void upload_with_retries(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::Batch *batch)
{
	for (uint32_t attempt = 0; attempt <= impl->config.max_retries; attempt++) {
		if (attempt > 0) {
			{
				std::lock_guard<std::mutex> lock(impl->mutex);
				impl->stats.retry_uploads++;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms(impl->config, attempt - 1)));
		}
		if (upload_once(impl, batch))
			return;
	}
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->stats.dropped_after_retries_batches++;
		impl->stats.dropped_after_retries_records += batch->record_count;
		impl->stats.dropped_after_retries_bytes += batch->used;
		impl->stats.failed_records += batch->record_count;
		impl->stats.failed_bytes += batch->used;
	}
	fprintf(stderr, "grpc drop batch after retries: records=%u bytes=%u attempts=%u\n",
		batch->record_count, batch->used, impl->config.max_retries + 1);
}

static AuditGrpcSender::Impl::Batch *pop_ready_batch(AuditGrpcSender::Impl *impl)
{
	std::unique_lock<std::mutex> lock(impl->mutex);
	while (true) {
		auto now = std::chrono::steady_clock::now();
		if (current_batch_expired_locked(impl, now))
			seal_current_batch_locked(impl);
		if (!impl->ready_batches.empty()) {
			AuditGrpcSender::Impl::Batch *batch = impl->ready_batches.front();
			impl->ready_batches.pop_front();
			sub_queued_locked(impl, batch);
			return batch;
		}
		if (impl->stopping) {
			seal_current_batch_locked(impl);
			if (impl->ready_batches.empty())
				return nullptr;
			continue;
		}
		if (impl->current_batch && impl->current_batch->record_count > 0 && impl->config.flush_interval_ms > 0) {
			auto deadline = impl->current_batch->first_record_time +
				std::chrono::milliseconds(impl->config.flush_interval_ms);
			impl->cond.wait_until(lock, deadline);
		} else {
			impl->cond.wait(lock);
		}
	}
}

static void sender_worker(AuditGrpcSender::Impl *impl)
{
	while (true) {
		AuditGrpcSender::Impl::Batch *batch = pop_ready_batch(impl);
		if (!batch)
			break;
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.active_workers++;
		}
		upload_with_retries(impl, batch);
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.active_workers--;
			impl->pool.release(batch);
			update_pool_stats_locked(impl);
		}
		impl->cond.notify_all();
	}
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

	audit_grpc_config normalized = config;
	normalized.agent_id = normalized.agent_id.empty() ? "default-agent" : normalized.agent_id;
	normalized.batch_bytes = default_or(normalized.batch_bytes, DEFAULT_GRPC_BATCH_BYTES);
	normalized.flush_interval_ms = default_or(normalized.flush_interval_ms, DEFAULT_GRPC_FLUSH_INTERVAL_MS);
	normalized.timeout_ms = default_or(normalized.timeout_ms, DEFAULT_GRPC_TIMEOUT_MS);
	normalized.pool_bytes = default_or64(normalized.pool_bytes, DEFAULT_GRPC_POOL_BYTES);
	normalized.upload_concurrency = std::min(default_or(normalized.upload_concurrency, DEFAULT_GRPC_UPLOAD_CONCURRENCY),
					       MAX_GRPC_UPLOAD_CONCURRENCY);
	normalized.max_retries = default_or(normalized.max_retries, DEFAULT_GRPC_MAX_RETRIES);
	normalized.retry_initial_ms = default_or(normalized.retry_initial_ms, DEFAULT_GRPC_RETRY_INITIAL_MS);
	normalized.retry_max_ms = default_or(normalized.retry_max_ms, DEFAULT_GRPC_RETRY_MAX_MS);

	uint32_t min_batches = normalized.upload_concurrency + 2;
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->config = normalized;
		if (!impl_->pool.init(normalized.pool_bytes, normalized.batch_bytes, min_batches)) {
			fprintf(stderr, "grpc batch pool init failed: pool_bytes=%llu batch_bytes=%u min_batches=%u\n",
				(unsigned long long)normalized.pool_bytes, normalized.batch_bytes, min_batches);
			return false;
		}
		impl_->ready_batches.clear();
		impl_->current_batch = nullptr;
		impl_->resolver = std::move(resolver);
		impl_->enabled = true;
		impl_->stopping = false;
		impl_->started = true;
		impl_->stats = audit_grpc_stats();
		reset_queue_counters_locked(impl_.get());
	}
	connect_current_collector(impl_.get());
	for (uint32_t i = 0; i < normalized.upload_concurrency; i++)
		impl_->workers.emplace_back(sender_worker, impl_.get());
	return true;
}

void AuditGrpcSender::stop()
{
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->started)
			return;
		impl_->stopping = true;
		seal_current_batch_locked(impl_.get());
	}
	impl_->cond.notify_all();
	for (auto &worker : impl_->workers) {
		if (worker.joinable())
			worker.join();
	}
	std::unique_ptr<CollectorResolver> resolver;
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->workers.clear();
		impl_->started = false;
		impl_->enabled = false;
		resolver = std::move(impl_->resolver);
		impl_->current_addr.clear();
		impl_->channel.reset();
		impl_->stub.reset();
		if (impl_->current_batch) {
			impl_->pool.release(impl_->current_batch);
			impl_->current_batch = nullptr;
		}
		for (auto *batch : impl_->ready_batches)
			impl_->pool.release(batch);
		impl_->ready_batches.clear();
		reset_queue_counters_locked(impl_.get());
	}
	if (resolver)
		resolver->stop();
}

bool AuditGrpcSender::submit(char *data, size_t size)
{
	if (!data || size == 0 || !impl_->enabled)
		return false;

#if AUDIT_PERF_FIELDS_ENABLED
	event *hdr = reinterpret_cast<event *>(data);
	hdr->perf_agent_after_submit_ns = monotonic_ns();
#endif
	std::lock_guard<std::mutex> lock(impl_->mutex);
	if (impl_->stopping) {
		impl_->stats.dropped_records++;
		impl_->stats.dropped_bytes += size;
		return false;
	}
	if (size > impl_->config.batch_bytes) {
		impl_->stats.dropped_records++;
		impl_->stats.dropped_bytes += size;
		impl_->stats.dropped_oversize_records++;
		impl_->stats.dropped_oversize_bytes += size;
		return false;
	}
	if (current_batch_expired_locked(impl_.get(), std::chrono::steady_clock::now()))
		seal_current_batch_locked(impl_.get());
	if (impl_->current_batch && impl_->current_batch->used + size > impl_->current_batch->capacity)
		seal_current_batch_locked(impl_.get());
	if (!impl_->current_batch) {
		impl_->current_batch = impl_->pool.acquire();
		if (!impl_->current_batch) {
			impl_->stats.dropped_records++;
			impl_->stats.dropped_bytes += size;
			impl_->stats.dropped_no_batch_records++;
			impl_->stats.dropped_no_batch_bytes += size;
			update_pool_stats_locked(impl_.get());
			return false;
		}
	}
	if (impl_->current_batch->record_count == 0)
		impl_->current_batch->first_record_time = std::chrono::steady_clock::now();
	memcpy(impl_->current_batch->data + impl_->current_batch->used, data, size);
	impl_->current_batch->used += (uint32_t)size;
	impl_->current_batch->record_count++;
	impl_->queued_records++;
	impl_->queued_bytes += size;
	if (impl_->current_batch->used >= impl_->current_batch->capacity)
		seal_current_batch_locked(impl_.get());
	update_pool_stats_locked(impl_.get());
	impl_->cond.notify_one();
	return true;
}

bool AuditGrpcSender::enabled() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->enabled;
}

std::string AuditGrpcSender::current_collector() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->current_addr;
}

bool AuditGrpcSender::wait_ready(uint32_t timeout_ms) const
{
	std::shared_ptr<grpc::Channel> channel;
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->enabled || !impl_->channel)
			return false;
		channel = impl_->channel;
	}
	return channel->WaitForConnected(std::chrono::system_clock::now() +
				       std::chrono::milliseconds(timeout_ms));
}

audit_grpc_stats AuditGrpcSender::stats() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->stats;
}
