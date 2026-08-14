// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_grpc_sender.h"
#include "uprobe.h"

#if AUDIT_GRPC_TIMING_ENABLED
#include <atomic>
#endif
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

#ifndef AUDIT_GRPC_TIMING_ENABLED
#define AUDIT_GRPC_TIMING_ENABLED 0
#endif

#if AUDIT_GRPC_TIMING_ENABLED
#define AUDIT_GRPC_TIMING_START(name) const uint64_t name##_start_ns = monotonic_ns()
#define AUDIT_GRPC_TIMING_END(name, total, maximum) \
	do { const uint64_t audit_timing_ns = monotonic_ns() - name##_start_ns; \
		total = audit_timing_ns; maximum = audit_timing_ns; } while (0)
#else
#define AUDIT_GRPC_TIMING_START(name)
#define AUDIT_GRPC_TIMING_END(name, total, maximum)
#endif

#include <grpcpp/grpcpp.h>
#include <grpc/grpc.h>
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
static constexpr uint32_t DEFAULT_GRPC_KEEPALIVE_TIME_MS = 15000;
static constexpr uint32_t DEFAULT_GRPC_KEEPALIVE_TIMEOUT_MS = 5000;
static constexpr uint32_t DISCOVERY_POLL_INTERVAL_MS = 200;

struct AuditGrpcSender::Impl {
	struct Batch {
		// Heap std::string owned by the batch. It is temporarily transferred into the
		// AuditBatch upload message via set_allocated_records() and reclaimed via
		// release_records(), so it must be an individually `new`-allocated object
		// (never an array element) to remain compatible with protobuf's delete.
		std::string *payload = nullptr;
		uint32_t record_count = 0;
		std::chrono::steady_clock::time_point first_record_time;
	};

	struct BatchPool {
		std::unique_ptr<Batch[]> batches;
		std::vector<uint32_t> free_indexes;
		std::vector<bool> free_flags;
		uint32_t batch_count = 0;
		uint32_t batch_bytes = 0;

		~BatchPool() { free_payloads(); }

		void free_payloads()
		{
			if (!batches)
				return;
			for (uint32_t i = 0; i < batch_count; i++) {
				delete batches[i].payload;
				batches[i].payload = nullptr;
			}
		}

		bool init(uint64_t pool_bytes, uint32_t batch_size, uint32_t min_batches)
		{
			if (batch_size == 0)
				return false;
			uint64_t count = pool_bytes / batch_size;
			if (count < min_batches || count > UINT32_MAX)
				return false;
			free_payloads();
			batches.reset(new (std::nothrow) Batch[count]);
			if (!batches)
				return false;
			free_indexes.clear();
			free_indexes.reserve((size_t)count);
			free_flags.assign((size_t)count, true);
			batch_count = (uint32_t)count;
			batch_bytes = batch_size;
			for (uint32_t i = 0; i < batch_count; i++) {
				batches[i].payload = new (std::nothrow) std::string();
				if (!batches[i].payload) {
					free_payloads();
					return false;
				}
				batches[i].payload->reserve(batch_bytes);
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
			batch->payload->clear();
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
			if (batch->payload)
				batch->payload->clear();
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
#if AUDIT_GRPC_TIMING_ENABLED
		std::vector<uint64_t> grpc_roundtrip_samples;
		std::atomic<bool> grpc_roundtrip_dirty{false};
#endif
		std::unique_ptr<CollectorResolver> resolver;
		std::string current_addr;
		std::string current_target;
		uint64_t set_version = 0;
		std::shared_ptr<grpc::Channel> channel;
		uint64_t channel_version = 0;
		bool switching = false;
		std::vector<std::thread> workers;
		std::thread discovery_thread;
		mutable std::mutex mutex;
		std::condition_variable cond;
		BatchPool pool;
		Batch *current_batch = nullptr;
		std::deque<Batch *> ready_batches;
		uint64_t queued_records = 0;
		uint64_t queued_bytes = 0;
		uint64_t active_records = 0;
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
	if (impl->stats.ready_batches > impl->stats.max_ready_batches)
		impl->stats.max_ready_batches = impl->stats.ready_batches;
}

static void sub_queued_locked(AuditGrpcSender::Impl *impl, const AuditGrpcSender::Impl::Batch *batch)
{
	impl->queued_records -= batch->record_count;
	impl->queued_bytes -= batch->payload->size();
	impl->active_records += batch->record_count;
	update_pool_stats_locked(impl);
}

static void complete_active_locked(AuditGrpcSender::Impl *impl, const AuditGrpcSender::Impl::Batch *batch)
{
	impl->active_records -= batch->record_count;
	update_pool_stats_locked(impl);
}

static void reset_queue_counters_locked(AuditGrpcSender::Impl *impl)
{
	impl->queued_records = 0;
	impl->queued_bytes = 0;
	update_pool_stats_locked(impl);
}

#if AUDIT_GRPC_TIMING_ENABLED
static void reset_grpc_roundtrip_timing_locked(AuditGrpcSender::Impl *impl)
{
	impl->grpc_roundtrip_samples.clear();
	impl->grpc_roundtrip_dirty.store(false, std::memory_order_relaxed);
}

static void add_grpc_roundtrip_timing_locked(AuditGrpcSender::Impl *impl, uint64_t grpc_roundtrip_ns)
{
	impl->stats.last_grpc_roundtrip_ns = grpc_roundtrip_ns;
	impl->stats.total_grpc_roundtrip_ns += grpc_roundtrip_ns;
	impl->stats.max_grpc_roundtrip_ns = std::max(impl->stats.max_grpc_roundtrip_ns, grpc_roundtrip_ns);
	impl->grpc_roundtrip_samples.push_back(grpc_roundtrip_ns);
	impl->grpc_roundtrip_dirty.store(true, std::memory_order_relaxed);
}

static void refresh_grpc_roundtrip_median_locked(AuditGrpcSender::Impl *impl)
{
	if (!impl->grpc_roundtrip_dirty.load(std::memory_order_relaxed))
		return;
	if (impl->grpc_roundtrip_samples.empty()) {
		impl->stats.median_grpc_roundtrip_ns = 0;
		impl->grpc_roundtrip_dirty.store(false, std::memory_order_relaxed);
		return;
	}
	std::vector<uint64_t> samples = impl->grpc_roundtrip_samples;
	const size_t mid = samples.size() / 2;
	std::nth_element(samples.begin(), samples.begin() + mid, samples.end());
	uint64_t median = samples[mid];
	if ((samples.size() & 1) == 0) {
		std::nth_element(samples.begin(), samples.begin() + mid - 1, samples.begin() + mid);
		median = (median + samples[mid - 1]) / 2;
	}
	impl->stats.median_grpc_roundtrip_ns = median;
	impl->grpc_roundtrip_dirty.store(false, std::memory_order_relaxed);
}
#endif
// 队列头部的batch是否满足达到发送时间间隔要求或者已经满了
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

struct SendTarget {
	std::string addr;
	std::shared_ptr<grpc::Channel> channel;
	uint64_t version = 0;
};

struct WorkerUploadState {
	uint64_t local_version = 0;
	std::unique_ptr<audit::AuditCollector::Stub> stub;
};

static std::string join_addrs(const std::vector<std::string> &addrs)
{
	std::string joined;
	for (size_t i = 0; i < addrs.size(); i++) {
		if (i)
			joined.push_back(',');
		joined += addrs[i];
	}
	return joined;
}

// Builds one multi-address gRPC channel using the built-in round_robin LB
// policy plus keepalive. addrs are "ip:port"; returns nullptr if empty.
static std::shared_ptr<grpc::Channel> build_lb_channel(const std::vector<std::string> &addrs,
						       const audit_grpc_config &cfg)
{
	if (addrs.empty())
		return nullptr;
	std::string target = "ipv4:" + join_addrs(addrs);
	grpc::ChannelArguments args;
	args.SetServiceConfigJSON(R"({"loadBalancingConfig":[{"round_robin":{}}]})");
	if (cfg.keepalive_time_ms > 0) {
		args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, (int)cfg.keepalive_time_ms);
		args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, cfg.keepalive_permit_without_calls ? 1 : 0);
		args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
	}
	if (cfg.keepalive_timeout_ms > 0)
		args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, (int)cfg.keepalive_timeout_ms);
	return grpc::CreateCustomChannel(target, grpc::InsecureChannelCredentials(), args);
}

// Reads the resolver's address set under impl->mutex (so the resolver cannot be
// destroyed concurrently) and, when the set changed (or force), rebuilds the
// round_robin channel outside the lock and atomically swaps it in using the
// switching guard.
static void rebuild_channel_from_resolver(AuditGrpcSender::Impl *impl, bool force)
{
	// Read the resolver's address set while holding impl->mutex so the resolver
	// object (owned by impl->resolver) cannot be reset/destroyed concurrently.
	// addresses() only takes the resolver's own lock and returns a copy, so it
	// is cheap and never re-enters impl->mutex. The expensive channel build
	// below stays outside the lock.
	uint64_t set_version = 0;
	std::vector<std::string> addrs;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (impl->stopping || !impl->enabled || !impl->resolver)
			return;
		addrs = impl->resolver->addresses(&set_version);
		if (!force && set_version == impl->set_version)
			return;
	}

	std::shared_ptr<grpc::Channel> channel = build_lb_channel(addrs, impl->config);
	std::string joined = join_addrs(addrs);

	{
		std::unique_lock<std::mutex> lock(impl->mutex);
		while (impl->switching && !impl->stopping)
			impl->cond.wait(lock);
		if (impl->stopping || !impl->enabled)
			return;
		impl->set_version = set_version;
		if (!channel) {
			// No addresses yet; keep any existing channel and wait for discovery.
			impl->cond.notify_all();
			return;
		}
		impl->switching = true;
	}

	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->channel = std::move(channel);
		impl->current_addr = joined;
		impl->current_target = joined;
		impl->channel_version++;
		impl->stats.channel_switches++;
		impl->switching = false;
	}
	impl->cond.notify_all();
	fprintf(stderr, "grpc rebuild collector channel: targets=%s set_version=%llu\n",
		joined.c_str(), (unsigned long long)set_version);
}

static bool get_send_target(AuditGrpcSender::Impl *impl, SendTarget *target)
{
	std::unique_lock<std::mutex> lock(impl->mutex);
	while (impl->switching && !impl->stopping)
		impl->cond.wait(lock);
	if (!impl->enabled || !impl->channel || impl->current_addr.empty())
		return false;
	target->addr = impl->current_addr;
	target->channel = impl->channel;
	target->version = impl->channel_version;
	return true;
}

static void discovery_loop(AuditGrpcSender::Impl *impl)
{
	std::unique_lock<std::mutex> lock(impl->mutex);
	while (!impl->stopping) {
		lock.unlock();
		rebuild_channel_from_resolver(impl, false);
		lock.lock();
		if (impl->stopping)
			break;
		impl->cond.wait_for(lock, std::chrono::milliseconds(DISCOVERY_POLL_INTERVAL_MS));
	}
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

static bool upload_once(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::Batch *local_batch,
				WorkerUploadState *worker_state)
{
	if (!local_batch || local_batch->payload->empty() || local_batch->record_count == 0)
		return true;

	const uint32_t payload_size = (uint32_t)local_batch->payload->size();

	SendTarget target;
	if (!get_send_target(impl, &target))
		return false;
	if (!worker_state->stub || worker_state->local_version != target.version) {
		worker_state->stub = audit::AuditCollector::NewStub(target.channel);
		worker_state->local_version = target.version;
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->stats.stub_rebuilds++;
	}

	audit::AuditBatch batch;
	batch.set_agent_id(impl->config.agent_id);
	batch.set_server_ip(impl->config.server_ip);
	batch.set_file_version(impl->config.file_version);
	batch.set_event_size(impl->config.event_size);
	batch.set_record_count(local_batch->record_count);
	// Zero-copy ownership move: hand the batch payload string to the message
	// instead of copying it (replaces set_records()). The reclaim guard moves
	// the pointer back out on every exit path so the batch buffer is reused and
	// protobuf never frees it.
	batch.set_allocated_records(local_batch->payload);
	struct ReclaimGuard {
		audit::AuditBatch *msg;
		AuditGrpcSender::Impl::Batch *b;
		~ReclaimGuard() { b->payload = msg->release_records(); }
	} reclaim_guard{&batch, local_batch};

	audit::UploadReply reply;
	grpc::ClientContext context;
	if (impl->config.timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() +
				     std::chrono::milliseconds(impl->config.timeout_ms));
#if AUDIT_GRPC_TIMING_ENABLED || AUDIT_PERF_FIELDS_ENABLED
	const uint64_t upload_start_ns = monotonic_ns();
#endif
	grpc::Status status = worker_state->stub->Upload(&context, batch, &reply);
#if AUDIT_GRPC_TIMING_ENABLED || AUDIT_PERF_FIELDS_ENABLED
	const uint64_t grpc_roundtrip_ns = monotonic_ns() - upload_start_ns;
#endif
	if (!status.ok() || !reply.ok()) {
		fprintf(stderr, "grpc upload failed: collector=%s records=%u bytes=%u grpc_status=%s reply_status=%d reply_message=%s\n",
			target.addr.c_str(), local_batch->record_count, payload_size,
			status.error_message().c_str(), reply.status(), reply.message().c_str());
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.failed_uploads++;
			if (status.ok() && !reply.ok()) {
				impl->stats.collector_rejected_records += local_batch->record_count;
				if (reply.status() == audit::UPLOAD_STATUS_QUEUE_FULL)
					impl->stats.collector_queue_full_records += local_batch->record_count;
			}
		}
		// Transient failures are handled by gRPC subchannel health/backoff on
		// the round_robin channel; batch retry re-reads the current channel.
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(impl->mutex);
#if AUDIT_GRPC_TIMING_ENABLED
			add_grpc_roundtrip_timing_locked(impl, grpc_roundtrip_ns);
#endif
			impl->stats.sent_batches++;
			impl->stats.sent_records += local_batch->record_count;
			impl->stats.acknowledged_records += reply.accepted_records();
			impl->stats.sent_bytes += payload_size;
	}
#if AUDIT_PERF_FIELDS_ENABLED
	std::string db_name = db_name_from_records(local_batch->payload->data(), payload_size);
	fprintf(stderr,
		"grpc upload perf: collector=%s db_name=%s records=%u bytes=%u roundtrip_us=%.3f\n",
		target.addr.c_str(), db_name.c_str(), local_batch->record_count, payload_size,
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

static void upload_with_retries(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::Batch *batch,
				WorkerUploadState *worker_state)
{
	for (uint32_t attempt = 0; attempt <= impl->config.max_retries; attempt++) {
		if (attempt > 0) {
			{
				std::lock_guard<std::mutex> lock(impl->mutex);
				impl->stats.retry_uploads++;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms(impl->config, attempt - 1)));
		}
		if (upload_once(impl, batch, worker_state))
			return;
	}
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		const uint32_t payload_size = (uint32_t)batch->payload->size();
		impl->stats.dropped_after_retries_batches++;
		impl->stats.dropped_after_retries_records += batch->record_count;
		impl->stats.dropped_after_retries_bytes += payload_size;
		impl->stats.failed_records += batch->record_count;
		impl->stats.failed_bytes += payload_size;
	}
	fprintf(stderr, "grpc drop batch after retries: records=%u bytes=%zu attempts=%u\n",
		batch->record_count, batch->payload->size(), impl->config.max_retries + 1);
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
	WorkerUploadState worker_state;
	while (true) {
		AuditGrpcSender::Impl::Batch *batch = pop_ready_batch(impl);
		if (!batch)
			break;
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.active_workers++;
			if (impl->stats.active_workers > impl->stats.max_active_workers)
				impl->stats.max_active_workers = impl->stats.active_workers;
		}
		upload_with_retries(impl, batch, &worker_state);
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.active_workers--;
			complete_active_locked(impl, batch);
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
	normalized.keepalive_time_ms = default_or(normalized.keepalive_time_ms, DEFAULT_GRPC_KEEPALIVE_TIME_MS);
	normalized.keepalive_timeout_ms = default_or(normalized.keepalive_timeout_ms, DEFAULT_GRPC_KEEPALIVE_TIMEOUT_MS);

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
		impl_->channel_version = 0;
		impl_->set_version = 0;
		impl_->switching = false;
#if AUDIT_GRPC_TIMING_ENABLED
		reset_grpc_roundtrip_timing_locked(impl_.get());
#endif
		reset_queue_counters_locked(impl_.get());
	}
	// Build the initial channel from the resolver's current set. For the static
	// path this yields a one-address round_robin channel. For etcd discovery
	// that is still empty, proceed anyway; the discovery thread builds it later.
	rebuild_channel_from_resolver(impl_.get(), true);
	for (uint32_t i = 0; i < normalized.upload_concurrency; i++)
		impl_->workers.emplace_back(sender_worker, impl_.get());
	impl_->discovery_thread = std::thread(discovery_loop, impl_.get());
	return true;
}

bool AuditGrpcSender::flush()
{
	std::unique_lock<std::mutex> lock(impl_->mutex);
	if (!impl_->started || impl_->stopping)
		return false;
	seal_current_batch_locked(impl_.get());
	impl_->cond.notify_all();
	impl_->cond.wait(lock, [this] {
		return impl_->queued_records == 0 && impl_->active_records == 0;
	});
	return true;
}

void AuditGrpcSender::stop()
{
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->started)
			return;
		impl_->stopping = true;
		impl_->switching = false;
		seal_current_batch_locked(impl_.get());
	}
	impl_->cond.notify_all();
	for (auto &worker : impl_->workers) {
		if (worker.joinable())
			worker.join();
	}
	if (impl_->discovery_thread.joinable())
		impl_->discovery_thread.join();
	std::unique_ptr<CollectorResolver> resolver;
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->workers.clear();
		impl_->started = false;
		impl_->enabled = false;
		resolver = std::move(impl_->resolver);
		impl_->current_addr.clear();
		impl_->current_target.clear();
		impl_->channel.reset();
		impl_->channel_version++;
		impl_->switching = false;
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
#if AUDIT_GRPC_TIMING_ENABLED
	const uint64_t submit_start_ns = monotonic_ns();
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
	auto now = std::chrono::steady_clock::now();
	if (current_batch_expired_locked(impl_.get(), now))
		seal_current_batch_locked(impl_.get());
	if (impl_->current_batch && impl_->current_batch->payload->size() + size > impl_->pool.batch_bytes)
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
	bool first_record = impl_->current_batch->record_count == 0;
	if (first_record)
		impl_->current_batch->first_record_time = now;
	impl_->stats.accepted_records++;
	impl_->current_batch->payload->append(data, size);
	impl_->current_batch->record_count++;
	impl_->queued_records++;
	impl_->queued_bytes += size;
	bool sealed = impl_->current_batch->payload->size() >= impl_->pool.batch_bytes;
	if (sealed)
		seal_current_batch_locked(impl_.get());
	update_pool_stats_locked(impl_.get());
	// seal 已 notify 就绪 batch；否则仅在新 batch 首条记录时唤醒 sender arm flush 截止时间，
	// 避免每条记录都 notify 造成的调度/futex churn。
	if (!sealed && first_record)
		impl_->cond.notify_one();
#if AUDIT_GRPC_TIMING_ENABLED
	const uint64_t submit_ns = monotonic_ns() - submit_start_ns;
	impl_->stats.submit_calls++;
	impl_->stats.total_submit_ns += submit_ns;
	if (submit_ns > impl_->stats.max_submit_ns)
		impl_->stats.max_submit_ns = submit_ns;
#endif
	return true;
}

bool AuditGrpcSender::report_metrics(const audit_agent_accounting_snapshot &snapshot)
{
	SendTarget target;
	if (!get_send_target(impl_.get(), &target))
		return false;
	auto stub = audit::AuditCollector::NewStub(target.channel);
	audit::MetricsReport report;
	report.set_source_type("agent");
	report.set_source_id(snapshot.source_id);
	report.set_server_ip(snapshot.server_ip);
	report.set_process_start_unix_ms(snapshot.process_start_unix_ms);
	report.set_sequence(snapshot.sequence);
	report.set_report_unix_ms(snapshot.report_unix_ms);
	audit::AgentAccounting *agent = report.mutable_agent();
	agent->set_ob_audit_seen_records(snapshot.ob_audit_seen_records);
	agent->set_ringbuf_lost_records(snapshot.ringbuf_lost_records);
	agent->set_agent_received_records(snapshot.agent_received_records);
	agent->set_pending_lost_records(snapshot.pending_lost_records);
	agent->set_send_enqueue_lost_records(snapshot.send_enqueue_lost_records);
	agent->set_collector_rejected_records(snapshot.collector_rejected_records);
	agent->set_collector_queue_full_records(snapshot.collector_queue_full_records);
	agent->set_upload_retry_exhausted_records(snapshot.upload_retry_exhausted_records);
	agent->set_agent_lost_records(snapshot.agent_lost_records);
	agent->set_delivered_records(snapshot.delivered_records);
	agent->set_acknowledged_records(snapshot.acknowledged_records);
	agent->set_inflight_records(snapshot.inflight_records);
	agent->set_sender_accepted_records(snapshot.sender_accepted_records);
	agent->set_pending_inflight_records(snapshot.pending_inflight_records);
	agent->set_sender_inflight_records(snapshot.sender_inflight_records);
	audit::MetricsReply reply;
	grpc::ClientContext context;
	if (impl_->config.timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() +
				     std::chrono::milliseconds(impl_->config.timeout_ms));
	grpc::Status status = stub->ReportMetrics(&context, report, &reply);
	return status.ok() && reply.ok();
}

bool AuditGrpcSender::enabled() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->enabled;
}

std::string AuditGrpcSender::current_collector() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->current_target;
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
#if AUDIT_GRPC_TIMING_ENABLED
	refresh_grpc_roundtrip_median_locked(impl_.get());
#endif
	return impl_->stats;
}
