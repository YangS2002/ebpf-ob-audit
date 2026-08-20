// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define main audit_collector_main_unused
#include "audit_collector.cpp"
#undef main

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

namespace {

std::string make_record_batch(unsigned int count)
{
	std::string records;
	for (unsigned int i = 0; i < count; i++) {
		event e = {};
		e.total_size = event_payload_offset();
		e.record_type = AUDIT_RECORD_EVENT;
		e.event_seq = i + 1;
		records.append(reinterpret_cast<const char *>(&e), e.total_size);
	}
	return records;
}

audit::AuditBatch make_batch(unsigned int count)
{
	audit::AuditBatch batch;
	std::string records = make_record_batch(count);
	batch.set_agent_id("agent-e2e");
	batch.set_server_ip("127.0.0.1");
	batch.set_file_version(AUDIT_FILE_VERSION);
	batch.set_event_size(sizeof(event));
	batch.set_record_count(count);
	batch.set_records(records.data(), records.size());
	return batch;
}

class CollectorServer {
public:
	explicit CollectorServer(AuditCollectorService *service)
	{
		grpc::ServerBuilder builder;
		builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
		builder.RegisterService(service);
		server_ = builder.BuildAndStart();
		if (server_)
			worker_ = std::thread([this] { server_->Wait(); });
	}

	~CollectorServer()
	{
		if (server_)
			server_->Shutdown();
		if (worker_.joinable())
			worker_.join();
	}

	std::unique_ptr<audit::AuditCollector::Stub> stub() const
	{
		auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port_), grpc::InsecureChannelCredentials());
		return audit::AuditCollector::NewStub(channel);
	}

	bool valid() const { return server_ != nullptr && port_ > 0; }

private:
	int port_ = 0;
	std::unique_ptr<grpc::Server> server_;
	std::thread worker_;
};

} // namespace

TEST(CollectorAsyncAckE2E, ValidUploadReturnsBeforeInsertCompletes)
{
	std::atomic<int> attempts{0};
	std::atomic<bool> release_insert{false};
	MongoInsertWorkerPool workers(nullptr, 1, 8, mongo_insert_complete_cb(),
		[&](const MongoInsertTask &task, unsigned int) {
			attempts++;
			while (!release_insert.load())
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
			mongo_insert_result result;
			result.ok = true;
			result.accepted_records = task.events().size();
			result.accepted_bytes = task.records_size();
			return result;
		});
	ASSERT_TRUE(workers.start());
	AuditCollectorService service("/tmp/audit_collector_async_ack_test.adt", nullptr, &workers, "collector-e2e", "127.0.0.1");
	CollectorServer server(&service);
	ASSERT_TRUE(server.valid());
	auto stub = server.stub();

	audit::UploadReply reply;
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(200));
	auto batch = make_batch(3);
	grpc::Status status = stub->Upload(&context, batch, &reply);
	EXPECT_TRUE(status.ok()) << status.error_message();
	EXPECT_TRUE(reply.ok());
	EXPECT_EQ(reply.accepted_records(), 3U);
	EXPECT_EQ(attempts.load(), 1);
	release_insert = true;
	workers.stop();
}

TEST(CollectorAsyncAckE2E, RetryExhaustionRecordsCollectorLoss)
{
	std::atomic<int> attempts{0};
	std::atomic<bool> completed{false};
	MongoInsertWorkerPool workers(nullptr, 1, 8,
		[&](const MongoInsertTask &, const mongo_insert_result &result) {
			EXPECT_FALSE(result.ok);
			completed = true;
		},
		[&](const MongoInsertTask &, unsigned int) {
			attempts++;
			mongo_insert_result result;
			result.ok = false;
			result.error = "injected insert failure";
			return result;
		});
	ASSERT_TRUE(workers.start());
	AuditCollectorService service("/tmp/audit_collector_retry_test.adt", nullptr, &workers, "collector-e2e", "127.0.0.1");
	CollectorServer server(&service);
	ASSERT_TRUE(server.valid());
	auto stub = server.stub();

	audit::UploadReply reply;
	grpc::ClientContext context;
	auto batch = make_batch(2);
	grpc::Status status = stub->Upload(&context, batch, &reply);
	ASSERT_TRUE(status.ok()) << status.error_message();
	ASSERT_TRUE(reply.ok());
	ASSERT_EQ(reply.accepted_records(), 2U);

	for (int i = 0; i < 100 && !completed.load(); i++)
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	EXPECT_TRUE(completed.load());
	EXPECT_EQ(attempts.load(), 4);
	workers.stop();
}
