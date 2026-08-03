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
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"

static constexpr uint32_t DEFAULT_GRPC_BATCH_BYTES = 262144;
static constexpr uint32_t DEFAULT_GRPC_FLUSH_INTERVAL_MS = 1000;
static constexpr uint32_t DEFAULT_GRPC_TIMEOUT_MS = 2000;
static constexpr uint64_t DEFAULT_GRPC_QUEUE_BYTES = 64ULL * 1024 * 1024;

struct AuditGrpcSender::Impl {
	struct QueuedRecord {
		std::string data;
	};

	struct LocalBatch {
		std::string records;
		uint64_t record_count = 0;
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
	std::thread worker;
	mutable std::mutex mutex;
	std::condition_variable cond;
	std::deque<QueuedRecord> queue;
	uint64_t queued_bytes = 0;
	FILE *failed_file = nullptr;
};

static const char *FAILED_RECORD_FILE = "audit_grpc_failed.adt";

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

static std::string db_name_from_records(const std::string &records)
{
	if (records.size() < event_payload_offset())
		return "";
	const event *e = reinterpret_cast<const event *>(records.data());
	if (!event_compact_size_valid(e))
		return "";
	return std::string(event_db_name(e), e->db_name_len);
}

static FILE *failed_file(AuditGrpcSender::Impl *impl)
{
	if (impl->failed_file)
		return impl->failed_file;
	impl->failed_file = fopen(FAILED_RECORD_FILE, "ab+");
	if (!impl->failed_file) {
		fprintf(stderr, "grpc failed record open failed: file=%s error=%s\n",
			FAILED_RECORD_FILE, strerror(errno));
		return nullptr;
	}
	if (fseek(impl->failed_file, 0, SEEK_END) == 0 && ftell(impl->failed_file) == 0) {
		audit_file_header header = {};
		memcpy(header.magic, AUDIT_FILE_MAGIC, sizeof(AUDIT_FILE_MAGIC));
		header.version = AUDIT_FILE_VERSION;
		header.header_size = sizeof(header);
		header.event_size = sizeof(event);
		if (fwrite(&header, sizeof(header), 1, impl->failed_file) != 1)
			fprintf(stderr, "grpc failed record header write failed: file=%s error=%s\n",
				FAILED_RECORD_FILE, strerror(errno));
	}
	return impl->failed_file;
}

static void write_failed_records(AuditGrpcSender::Impl *impl, const std::string &records,
				 uint64_t record_count, const char *reason)
{
	if (records.empty() || record_count == 0)
		return;
	FILE *file = failed_file(impl);
	bool written = false;
	if (file) {
		written = fwrite(records.data(), 1, records.size(), file) == records.size();
		fflush(file);
	}
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->stats.failed_records += record_count;
		impl->stats.failed_bytes += records.size();
	}
	fprintf(stderr,
		"grpc failed records: reason=%s records=%llu bytes=%zu file=%s persisted=%s\n",
		reason, (unsigned long long)record_count, records.size(), FAILED_RECORD_FILE,
		written ? "true" : "false");
}

static void append_record(AuditGrpcSender::Impl::LocalBatch *batch,
			  AuditGrpcSender::Impl::QueuedRecord &&record)
{
	batch->records.append(record.data.data(), record.data.size());
	batch->record_count++;
}

static bool batch_full(const AuditGrpcSender::Impl::LocalBatch &batch, size_t next_size,
		       uint32_t batch_bytes)
{
	return batch.record_count > 0 && batch_bytes > 0 && batch.records.size() + next_size > batch_bytes;
}

static bool upload_batch(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::LocalBatch &local_batch)
{
	if (local_batch.records.empty())
		return true;
	if (!impl->stub && !connect_current_collector(impl)) {
		write_failed_records(impl, local_batch.records, local_batch.record_count, "connect_failed");
		return false;
	}

	std::unique_ptr<audit::AuditCollector::Stub> stub;
	std::string current_addr;
	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		if (!impl->enabled) {
			write_failed_records(impl, local_batch.records, local_batch.record_count, "disabled");
			return false;
		}
		if (!impl->stub) {
			write_failed_records(impl, local_batch.records, local_batch.record_count, "no_stub");
			return false;
		}
		stub = std::move(impl->stub);
		current_addr = impl->current_addr;
	}

	audit::AuditBatch batch;
	batch.set_agent_id(impl->config.agent_id);
	batch.set_server_ip(impl->config.server_ip);
	batch.set_file_version(impl->config.file_version);
	batch.set_event_size(impl->config.event_size);
	batch.set_record_count(local_batch.record_count);
	const size_t record_bytes = local_batch.records.size();
	std::string db_name = db_name_from_records(local_batch.records);
	batch.mutable_records()->swap(local_batch.records);

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
		if (impl->current_addr == current_addr) {
			impl->stub = std::move(stub);
			if (!status.ok() || !reply.ok())
				impl->stub.reset();
		}
	}
	if (!status.ok() || !reply.ok()) {
		fprintf(stderr, "grpc upload failed: collector=%s records=%llu bytes=%zu %s %s\n",
			current_addr.c_str(), (unsigned long long)local_batch.record_count, record_bytes,
			status.error_message().c_str(), reply.message().c_str());
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			impl->stats.failed_uploads++;
		}
		write_failed_records(impl, batch.records(), local_batch.record_count, "upload_failed");
		switch_collector(impl);
		local_batch.record_count = 0;
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(impl->mutex);
		impl->stats.last_grpc_roundtrip_ns = grpc_roundtrip_ns;
		impl->stats.total_grpc_roundtrip_ns += grpc_roundtrip_ns;
		impl->stats.max_grpc_roundtrip_ns = std::max(impl->stats.max_grpc_roundtrip_ns, grpc_roundtrip_ns);
		impl->stats.sent_batches++;
		impl->stats.sent_records += local_batch.record_count;
		impl->stats.sent_bytes += record_bytes;
	}
	fprintf(stderr,
		"grpc upload perf: collector=%s db_name=%s records=%llu bytes=%zu roundtrip_us=%.3f\n",
		current_addr.c_str(), db_name.c_str(), (unsigned long long)local_batch.record_count, record_bytes,
		(double)grpc_roundtrip_ns / 1000.0);
	local_batch.records.clear();
	local_batch.record_count = 0;
	return true;
}

static bool build_local_batch(AuditGrpcSender::Impl *impl, AuditGrpcSender::Impl::LocalBatch *batch)
{
	std::unique_lock<std::mutex> lock(impl->mutex);
	impl->cond.wait(lock, [&] { return impl->stopping || !impl->queue.empty(); });
	if (impl->queue.empty())
		return false;

	const uint32_t batch_bytes = impl->config.batch_bytes;
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(impl->config.flush_interval_ms);

	while (true) {
		while (!impl->queue.empty()) {
			const size_t next_size = impl->queue.front().data.size();
			if (batch_full(*batch, next_size, batch_bytes))
				goto done;
			AuditGrpcSender::Impl::QueuedRecord record = std::move(impl->queue.front());
			impl->queue.pop_front();
			impl->queued_bytes -= next_size;
			append_record(batch, std::move(record));
			if (batch_bytes > 0 && batch->records.size() >= batch_bytes)
				goto done;
		}
		if (impl->stopping || batch->record_count == 0 || impl->config.flush_interval_ms == 0)
			goto done;
		if (!impl->cond.wait_until(lock, deadline, [&] { return impl->stopping || !impl->queue.empty(); }))
			goto done;
		if (impl->stopping && impl->queue.empty())
			goto done;
	}

done:
	impl->stats.queued_records = impl->queue.size();
	impl->stats.queued_bytes = impl->queued_bytes;
	return batch->record_count > 0;
}

static void sender_worker(AuditGrpcSender::Impl *impl)
{
	while (true) {
		AuditGrpcSender::Impl::LocalBatch batch;
		if (!build_local_batch(impl, &batch)) {
			std::lock_guard<std::mutex> lock(impl->mutex);
			if (impl->stopping && impl->queue.empty())
				break;
			continue;
		}
		bool stopping = false;
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			stopping = impl->stopping;
		}
		if (stopping)
			write_failed_records(impl, batch.records, batch.record_count, "stopping");
		else
			upload_batch(impl, batch);
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

	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->config = config;
		impl_->config.agent_id = impl_->config.agent_id.empty() ? "default-agent" : impl_->config.agent_id;
			// 0 表示配置文件未显式设置，统一回退到 agent 默认值。
			impl_->config.batch_bytes = default_or(impl_->config.batch_bytes, DEFAULT_GRPC_BATCH_BYTES);
			impl_->config.flush_interval_ms = default_or(impl_->config.flush_interval_ms, DEFAULT_GRPC_FLUSH_INTERVAL_MS);
			impl_->config.timeout_ms = default_or(impl_->config.timeout_ms, DEFAULT_GRPC_TIMEOUT_MS);
			impl_->config.queue_bytes = default_or64(impl_->config.queue_bytes, DEFAULT_GRPC_QUEUE_BYTES);
		impl_->resolver = std::move(resolver);
		impl_->enabled = true;
		impl_->stopping = false;
		impl_->started = true;
	}
	connect_current_collector(impl_.get());
	impl_->worker = std::thread(sender_worker, impl_.get());
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
	std::unique_ptr<CollectorResolver> resolver;
	FILE *failed_file = nullptr;
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->started = false;
		impl_->enabled = false;
		resolver = std::move(impl_->resolver);
		impl_->current_addr.clear();
		impl_->channel.reset();
		impl_->stub.reset();
		impl_->queue.clear();
		impl_->queued_bytes = 0;
		failed_file = impl_->failed_file;
		impl_->failed_file = nullptr;
	}
	if (failed_file)
		fclose(failed_file);
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
	std::string record(data, size);

	std::lock_guard<std::mutex> lock(impl_->mutex);
	if (impl_->stopping || impl_->queued_bytes + record.size() > impl_->config.queue_bytes) {
		impl_->stats.dropped_records++;
		impl_->stats.dropped_bytes += size;
		return false;
	}
	impl_->queue.push_back(Impl::QueuedRecord{std::move(record)});
	impl_->queued_bytes += size;
	impl_->stats.queued_records = impl_->queue.size();
	impl_->stats.queued_bytes = impl_->queued_bytes;
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
