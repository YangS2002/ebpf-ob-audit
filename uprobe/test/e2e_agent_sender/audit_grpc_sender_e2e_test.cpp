// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "audit_grpc_sender.h"
#include "audit_upload.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
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

private:
	Mode mode_;
	int failures_before_ok_ = 0;
	std::atomic<int> upload_calls_{0};
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
