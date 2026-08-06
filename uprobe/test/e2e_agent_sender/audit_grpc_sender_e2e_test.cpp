// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_grpc_sender.h"
#include "audit_upload.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
// e2e测试
// 测试grpc的上传功能,使用fake collector
// 1. SealsBatchBySize: 测试batch的大小限制,当达到batch_bytes时,会触发上传
// 2. SealsBatchByTime: 测试batch的时间限制,当达到flush_interval_ms时,会触发上传
// 4. DropsWhenPoolExhausted: 测试pool的大小限制,当达到pool_bytes时,会触发丢弃
// 5. RetriesThenSucceeds: 失败后原地重试固定次数,短暂故障恢复后成功
// 6. DropsAfterRetryExhaustion: 失败后原地尝试固定次数,超过次数后丢弃
namespace {

class FakeCollector final : public audit::AuditCollector::Service {
public:
	enum class Mode {
		AlwaysOk,
		FailThenOk,
		AlwaysFail,
		Block,
	};

	struct ReceivedBatch {
		uint64_t record_count = 0;
		size_t bytes = 0;
		std::string agent_id;
		std::string server_ip;
	};

	explicit FakeCollector(Mode mode = Mode::AlwaysOk, int failures_before_ok = 0)
		: mode_(mode), failures_before_ok_(failures_before_ok)
	{
	}

	grpc::Status Upload(grpc::ServerContext *, const audit::AuditBatch *request,
			    audit::UploadReply *reply) override
	{
		int call = ++upload_calls_;
		cond_.notify_all();
		{
			std::unique_lock<std::mutex> lock(mutex_);
			while (mode_ == Mode::Block && !unblock_)
				cond_.wait(lock);
		}

		int64_t delay_us = delay_us_.load();
		if (delay_us > 0)
			std::this_thread::sleep_for(std::chrono::microseconds(delay_us));

		bool ok = mode_ == Mode::AlwaysOk || (mode_ == Mode::FailThenOk && call > failures_before_ok_);
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (ok) {
				received_.push_back(ReceivedBatch{
					request->record_count(), request->records().size(), request->agent_id(), request->server_ip()});
			}
		}
		cond_.notify_all();
		reply->set_ok(ok);
		reply->set_message(ok ? "ok" : "fail");
		reply->set_accepted_records(ok ? request->record_count() : 0);
		reply->set_accepted_bytes(ok ? request->records().size() : 0);
		return grpc::Status::OK;
	}

	void unblock()
	{
		{
			std::lock_guard<std::mutex> lock(mutex_);
			unblock_ = true;
		}
		cond_.notify_all();
	}

	bool wait_for_batches(size_t count, std::chrono::milliseconds timeout)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		return cond_.wait_for(lock, timeout, [&] { return received_.size() >= count; });
	}

	bool wait_for_calls(int count, std::chrono::milliseconds timeout)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		return cond_.wait_for(lock, timeout, [&] { return upload_calls_.load() >= count; });
	}

	size_t received_count() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return received_.size();
	}

	uint64_t received_records() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		uint64_t total = 0;
		for (const auto &batch : received_)
			total += batch.record_count;
		return total;
	}

	std::vector<ReceivedBatch> received() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return received_;
	}

	int upload_calls() const { return upload_calls_.load(); }

	void set_response_delay_us(int64_t us) { delay_us_ = us; }

private:
	Mode mode_;
	int failures_before_ok_ = 0;
	std::atomic<int> upload_calls_{0};
	std::atomic<int64_t> delay_us_{0};
	mutable std::mutex mutex_;
	std::condition_variable cond_;
	std::vector<ReceivedBatch> received_;
	bool unblock_ = false;
};

class FakeCollectorServer {
public:
	FakeCollectorServer(FakeCollector::Mode mode = FakeCollector::Mode::AlwaysOk, int failures_before_ok = 0)
		: collector_(mode, failures_before_ok)
	{
		grpc::ServerBuilder builder;
		builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
		builder.RegisterService(&collector_);
		server_ = builder.BuildAndStart();
		if (server_)
			worker_ = std::thread([this] { server_->Wait(); });
	}

	~FakeCollectorServer()
	{
		if (server_)
			server_->Shutdown();
		if (worker_.joinable())
			worker_.join();
	}

	std::string addr() const { return "127.0.0.1:" + std::to_string(port_); }
	FakeCollector &collector() { return collector_; }
	bool valid() const { return server_ != nullptr && port_ > 0; }

private:
	FakeCollector collector_;
	int port_ = 0;
	std::unique_ptr<grpc::Server> server_;
	std::thread worker_;
};

audit_grpc_config base_config(const std::string &addr)
{
	audit_grpc_config config;
	config.agent_id = "agent-test";
	config.server_ip = "127.0.0.1";
	config.collector_addr = addr;
	config.file_version = 1;
	config.event_size = 64;
	config.batch_bytes = 256;
	config.flush_interval_ms = 50;
	config.timeout_ms = 200;
	config.pool_bytes = 1024;
	config.upload_concurrency = 1;
	config.max_retries = 3;
	config.retry_initial_ms = 1;
	config.retry_max_ms = 2;
	return config;
}

std::vector<char> record(size_t size, char value)
{
	std::vector<char> data(size, value);
	return data;
}

void submit_record(AuditGrpcSender &sender, std::vector<char> &data)
{
	ASSERT_TRUE(sender.submit(data.data(), data.size()));
}

uint64_t monotonic_ns()
{
	return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

void upload_batch(audit::AuditCollector::Stub *stub, const std::vector<char> &payload)
{
	audit::AuditBatch batch;
	batch.set_agent_id("bench-agent");
	batch.set_server_ip("127.0.0.1");
	batch.set_file_version(1);
	batch.set_event_size(64);
	batch.set_record_count(payload.size() / 64);
	batch.set_records(payload.data(), payload.size());

	audit::UploadReply reply;
	grpc::ClientContext context;
	ASSERT_TRUE(stub->Upload(&context, batch, &reply).ok());
	ASSERT_TRUE(reply.ok());
}

} // namespace

TEST(AuditGrpcSenderE2E, SealsBatchBySize)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.batch_bytes = 128;
	config.pool_bytes = 512;
	config.flush_interval_ms = 10000;
	ASSERT_TRUE(sender.start(config));

	auto r1 = record(80, 'a');
	auto r2 = record(80, 'b');
	submit_record(sender, r1);
	submit_record(sender, r2);

	ASSERT_TRUE(server.collector().wait_for_batches(1, std::chrono::seconds(2)));
	sender.stop();
	ASSERT_GE(server.collector().received_count(), 1U);
}

TEST(AuditGrpcSenderE2E, SealsBatchByTime)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.batch_bytes = 4096;
	config.pool_bytes = 16384;
	config.flush_interval_ms = 20;
	ASSERT_TRUE(sender.start(config));

	auto r = record(64, 'a');
	submit_record(sender, r);

	ASSERT_TRUE(server.collector().wait_for_batches(1, std::chrono::seconds(2)));
	sender.stop();
	ASSERT_EQ(server.collector().received_count(), 1U);
}

TEST(AuditGrpcSenderE2E, DropsWhenPoolExhausted)
{
	FakeCollectorServer server(FakeCollector::Mode::Block);
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.batch_bytes = 128;
	config.pool_bytes = 384;
	config.flush_interval_ms = 10000;
	config.upload_concurrency = 1;
	ASSERT_TRUE(sender.start(config));

	std::vector<std::vector<char>> records;
	for (int i = 0; i < 20; i++)
		records.push_back(record(80, (char)('a' + i)));
	for (auto &r : records)
		sender.submit(r.data(), r.size());

	ASSERT_TRUE(server.collector().wait_for_calls(1, std::chrono::seconds(2)));
	audit_grpc_stats stats = sender.stats();
	EXPECT_GT(stats.dropped_no_batch_records, 0U);
	server.collector().unblock();
	sender.stop();
}

TEST(AuditGrpcSenderE2E, RetriesThenSucceeds)
{
	FakeCollectorServer server(FakeCollector::Mode::FailThenOk, 2);
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.max_retries = 3;
	ASSERT_TRUE(sender.start(config));

	auto r = record(64, 'a');
	submit_record(sender, r);

	ASSERT_TRUE(server.collector().wait_for_batches(1, std::chrono::seconds(3)));
	sender.stop();
	audit_grpc_stats stats = sender.stats();
	EXPECT_GE(stats.retry_uploads, 2U);
	EXPECT_EQ(stats.sent_batches, 1U);
	EXPECT_EQ(stats.dropped_after_retries_batches, 0U);
}

TEST(AuditGrpcSenderE2E, DropsAfterRetryExhaustion)
{
	FakeCollectorServer server(FakeCollector::Mode::AlwaysFail);
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.max_retries = 3;
	ASSERT_TRUE(sender.start(config));

	auto r = record(64, 'a');
	submit_record(sender, r);

	ASSERT_TRUE(server.collector().wait_for_calls(4, std::chrono::seconds(3)));
	sender.stop();
	audit_grpc_stats stats = sender.stats();
	EXPECT_EQ(stats.dropped_after_retries_batches, 1U);
	EXPECT_EQ(stats.dropped_after_retries_records, 1U);
	EXPECT_EQ(stats.sent_batches, 0U);
}

TEST(AuditGrpcSenderE2E, ChannelReuseBenchmark)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());

	constexpr int warmup_batches = 20;
	constexpr int bench_batches = 500;
	const auto payload = record(64 * 64, 'x');

	for (int i = 0; i < warmup_batches; i++) {
		auto channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
		auto stub = audit::AuditCollector::NewStub(channel);
		upload_batch(stub.get(), payload);
	}

	uint64_t recreate_start_ns = monotonic_ns();
	for (int i = 0; i < bench_batches; i++) {
		auto channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
		auto stub = audit::AuditCollector::NewStub(channel);
		upload_batch(stub.get(), payload);
	}
	uint64_t recreate_ns = monotonic_ns() - recreate_start_ns;

	auto channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
	for (int i = 0; i < warmup_batches; i++) {
		auto stub = audit::AuditCollector::NewStub(channel);
		upload_batch(stub.get(), payload);
	}

	uint64_t reuse_start_ns = monotonic_ns();
	for (int i = 0; i < bench_batches; i++) {
		auto stub = audit::AuditCollector::NewStub(channel);
		upload_batch(stub.get(), payload);
	}
	uint64_t reuse_ns = monotonic_ns() - reuse_start_ns;

	fprintf(stderr,
		"channel benchmark: batches=%d payload_bytes=%zu recreate_total_ms=%.3f recreate_avg_us=%.3f reuse_total_ms=%.3f reuse_avg_us=%.3f speedup=%.2fx\n",
		bench_batches, payload.size(), recreate_ns / 1000000.0, recreate_ns / 1000.0 / bench_batches,
		reuse_ns / 1000000.0, reuse_ns / 1000.0 / bench_batches, (double)recreate_ns / (double)reuse_ns);

	EXPECT_EQ(server.collector().received_records(), (uint64_t)(warmup_batches * 2 + bench_batches * 2) * 64);
}

TEST(AuditGrpcSenderE2E, ConcurrentChannelReuseBenchmark)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());

	constexpr int worker_count = 4;
	constexpr int batches_per_worker = 200;
	constexpr size_t record_size = 64;
	const size_t records_per_batch = 256 * 1024 / record_size;
	const auto payload = record(records_per_batch * record_size, 'x');

	auto run_workers = [&](const std::function<void()> &body) {
		std::vector<std::thread> workers;
		for (int i = 0; i < worker_count; i++)
			workers.emplace_back(body);
		for (auto &worker : workers)
			worker.join();
	};

	// A: each batch creates its own channel + stub, mirroring current upload_once()
	uint64_t recreate_start_ns = monotonic_ns();
	run_workers([&] {
		for (int i = 0; i < batches_per_worker; i++) {
			auto channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
			auto stub = audit::AuditCollector::NewStub(channel);
			upload_batch(stub.get(), payload);
		}
	});
	uint64_t recreate_ns = monotonic_ns() - recreate_start_ns;

	// B: one shared channel across all workers, each RPC only creates a stub
	auto shared_channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
	{
		auto warmup_stub = audit::AuditCollector::NewStub(shared_channel);
		upload_batch(warmup_stub.get(), payload);
	}
	uint64_t reuse_start_ns = monotonic_ns();
	run_workers([&] {
		for (int i = 0; i < batches_per_worker; i++) {
			auto stub = audit::AuditCollector::NewStub(shared_channel);
			upload_batch(stub.get(), payload);
		}
	});
	uint64_t reuse_ns = monotonic_ns() - reuse_start_ns;

	// C: one reused channel per worker (channel pool sized to concurrency)
	std::vector<std::shared_ptr<grpc::Channel>> worker_channels(worker_count);
	for (auto &channel : worker_channels) {
		channel = grpc::CreateChannel(server.addr(), grpc::InsecureChannelCredentials());
		auto warmup_stub = audit::AuditCollector::NewStub(channel);
		upload_batch(warmup_stub.get(), payload);
	}
	std::atomic<int> worker_index{0};
	uint64_t pool_start_ns = monotonic_ns();
	run_workers([&] {
		auto channel = worker_channels[worker_index++];
		for (int i = 0; i < batches_per_worker; i++) {
			auto stub = audit::AuditCollector::NewStub(channel);
			upload_batch(stub.get(), payload);
		}
	});
	uint64_t pool_ns = monotonic_ns() - pool_start_ns;

	const int total_batches = worker_count * batches_per_worker;
	fprintf(stderr,
		"concurrent channel benchmark: workers=%d batches=%d payload_bytes=%zu recreate_avg_us=%.3f shared_reuse_avg_us=%.3f pool_reuse_avg_us=%.3f shared_speedup=%.2fx pool_speedup=%.2fx\n",
		worker_count, total_batches, payload.size(), recreate_ns / 1000.0 / total_batches,
		reuse_ns / 1000.0 / total_batches, pool_ns / 1000.0 / total_batches,
		(double)recreate_ns / (double)reuse_ns, (double)recreate_ns / (double)pool_ns);

	EXPECT_EQ(server.collector().received_records(),
		  (uint64_t)(total_batches * 3 + 1 + worker_count) * records_per_batch);
}

TEST(AuditGrpcSenderE2E, SingleSubmitterUsesMultipleWorkers)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.batch_bytes = 512;
	config.pool_bytes = 65536;
	config.flush_interval_ms = 10000;
	config.upload_concurrency = 4;
	ASSERT_TRUE(sender.start(config));

	constexpr int record_count = 400;
	for (int i = 0; i < record_count; i++) {
		auto data = record(64, (char)('a' + (i % 26)));
		ASSERT_TRUE(sender.submit(data.data(), data.size()));
	}

	sender.stop();
	EXPECT_EQ(server.collector().received_records(), (uint64_t)record_count);

	audit_grpc_stats stats = sender.stats();
	EXPECT_EQ(stats.sent_records, (uint64_t)record_count);
	EXPECT_EQ(stats.dropped_records, 0U);
}

// 压测:单生产者 submit,回答两问
//   Q1 8 worker 是否浪费  -> max_active_workers / max_ready_batches
//   Q2 submit 单线程是否瓶颈 -> submit_qps / avg_submit_us
// env 可调:
//   BENCH_RECORDS     总记录数(默认 500000)
//   BENCH_RTT_US      collector 每次 Upload 注入延迟 us(默认 0,模拟网络RTT+处理)
//   BENCH_TARGET_QPS  submit 限速(0=不限速,测最大吞吐;>0=按目标qps灌,测worker够不够)
//   BENCH_WORKERS     上传并发(默认 8)
// 结果同时打印到 stderr 并追加到 grpc_submit_bench.txt
TEST(AuditGrpcSenderE2E, SubmitThroughputBenchmark)
{
	auto env_ll = [](const char *name, int64_t def) -> int64_t {
		const char *v = std::getenv(name);
		return v ? std::atoll(v) : def;
	};
	const int total_records = (int)env_ll("BENCH_RECORDS", 500000);
	const int64_t rtt_us = env_ll("BENCH_RTT_US", 0);
	const int64_t target_qps = env_ll("BENCH_TARGET_QPS", 0);
	const uint32_t workers = (uint32_t)env_ll("BENCH_WORKERS", 8);

	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());
	server.collector().set_response_delay_us(rtt_us);

	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.event_size = 256;
	config.batch_bytes = 262144;
	config.pool_bytes = 64ULL * 1024 * 1024;
	config.flush_interval_ms = 1000;
	config.timeout_ms = 2000;
	config.upload_concurrency = workers;
	config.max_retries = 0;
	ASSERT_TRUE(sender.start(config));

	auto data = record(256, 'x');
	const uint64_t start_ns = monotonic_ns();
	const double target_interval_ns = target_qps > 0 ? 1e9 / (double)target_qps : 0;
	for (int i = 0; i < total_records; i++) {
		sender.submit(data.data(), data.size());
		if (target_qps > 0) {
			double expected_ns = (double)(i + 1) * target_interval_ns;
			double elapsed_ns = (double)(monotonic_ns() - start_ns);
			if (elapsed_ns < expected_ns)
				std::this_thread::sleep_for(
					std::chrono::nanoseconds((int64_t)(expected_ns - elapsed_ns)));
		}
	}
	const uint64_t submit_done_ns = monotonic_ns();
	sender.stop();
	const uint64_t drain_done_ns = monotonic_ns();

	audit_grpc_stats stats = sender.stats();
	double submit_secs = (submit_done_ns - start_ns) / 1e9;
	double submit_qps = submit_secs > 0 ? total_records / submit_secs : 0;
#if AUDIT_GRPC_TIMING_ENABLED
	double avg_submit_us = stats.submit_calls
		? (double)stats.total_submit_ns / stats.submit_calls / 1000.0 : 0;
	double avg_rtt_us = stats.sent_batches
		? (double)stats.total_grpc_roundtrip_ns / stats.sent_batches / 1000.0 : 0;
#endif

	char line[1024];
#if AUDIT_GRPC_TIMING_ENABLED
	snprintf(line, sizeof(line),
		"submit_bench rtt_us=%lld target_qps=%lld workers=%u records=%d "
		"submit_qps=%.0f submit_wall_s=%.3f drain_extra_s=%.3f "
		"avg_submit_us=%.3f max_submit_us=%.3f "
		"sent_records=%llu dropped_records=%llu dropped_no_batch=%llu "
		"max_active_workers=%u max_ready_batches=%u sent_batches=%llu "
		"avg_rtt_us=%.3f max_rtt_us=%.3f\n",
		(long long)rtt_us, (long long)target_qps, workers, total_records,
		submit_qps, submit_secs, (drain_done_ns - submit_done_ns) / 1e9,
		avg_submit_us, stats.max_submit_ns / 1000.0,
		(unsigned long long)stats.sent_records,
		(unsigned long long)stats.dropped_records,
		(unsigned long long)stats.dropped_no_batch_records,
		stats.max_active_workers, stats.max_ready_batches,
		(unsigned long long)stats.sent_batches,
		avg_rtt_us, stats.max_grpc_roundtrip_ns / 1000.0);
#else
	snprintf(line, sizeof(line),
		"submit_bench rtt_us=%lld target_qps=%lld workers=%u records=%d "
		"submit_qps=%.0f submit_wall_s=%.3f drain_extra_s=%.3f "
		"sent_records=%llu dropped_records=%llu dropped_no_batch=%llu "
		"max_active_workers=%u max_ready_batches=%u sent_batches=%llu\n",
		(long long)rtt_us, (long long)target_qps, workers, total_records,
		submit_qps, submit_secs, (drain_done_ns - submit_done_ns) / 1e9,
		(unsigned long long)stats.sent_records,
		(unsigned long long)stats.dropped_records,
		(unsigned long long)stats.dropped_no_batch_records,
		stats.max_active_workers, stats.max_ready_batches,
		(unsigned long long)stats.sent_batches);
#endif
	fputs(line, stderr);
	FILE *f = fopen("grpc_submit_bench.txt", "a");
	if (f) {
		fputs(line, f);
		fclose(f);
	}
}

TEST(AuditGrpcSenderE2E, StopDrainsPendingBatch)
{
	FakeCollectorServer server;
	ASSERT_TRUE(server.valid());
	AuditGrpcSender sender;
	auto config = base_config(server.addr());
	config.flush_interval_ms = 10000;
	ASSERT_TRUE(sender.start(config));

	auto r = record(64, 'a');
	submit_record(sender, r);
	sender.stop();

	EXPECT_EQ(server.collector().received_count(), 1U);
}
