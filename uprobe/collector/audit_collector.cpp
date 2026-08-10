// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"
#include "audit_event_parser.h"
#include "collector_registry.h"
#include "collector_timing.h"
#include "mongodb_sink.h"
#include "mongo_insert_worker.h"
#include "simple_yaml.h"
#include "uprobe.h"

#if AUDIT_PERF_FIELDS_ENABLED
static unsigned long long monotonic_ns()
{
	return COLLECTOR_TIMING_NOW();
}
#endif

class AuditCollectorService final : public audit::AuditCollector::Service {
public:
	explicit AuditCollectorService(const std::string &output_path, MongoSink *mongo_sink = nullptr,
				      MongoInsertWorkerPool *mongo_workers = nullptr,
				      const std::string &collector_id = "", const std::string &listen_addr = "")
		: mongo_sink_(mongo_sink), mongo_workers_(mongo_workers), collector_id_(collector_id), listen_addr_(listen_addr)
	{
		file_ = fopen(output_path.c_str(), "ab");
		if (!file_) {
			fprintf(stderr, "Failed to open %s: %s\n", output_path.c_str(), strerror(errno));
			exit(1);
		}
		if (ftell(file_) == 0) {
			audit_file_header header = {};
			memcpy(header.magic, AUDIT_FILE_MAGIC, sizeof(AUDIT_FILE_MAGIC));
			header.version = AUDIT_FILE_VERSION;
			header.header_size = sizeof(header);
			header.event_size = sizeof(event);
			fwrite(&header, sizeof(header), 1, file_);
		}
	}

	~AuditCollectorService() override
	{
		if (file_)
			fclose(file_);
	}

	grpc::Status Upload(grpc::ServerContext *, const audit::AuditBatch *request,
				    audit::UploadReply *reply) override
	{
		[[maybe_unused]] const unsigned long long upload_start_ns = COLLECTOR_TIMING_NOW();
		if (request->file_version() != AUDIT_FILE_VERSION || request->event_size() != sizeof(event)) {
			reply->set_ok(false);
			reply->set_message("version or event_size mismatch");
			return grpc::Status::OK;
		}
#if AUDIT_PERF_FIELDS_ENABLED
		std::string records = request->records();
#else
		const std::string &records = request->records();
#endif
		std::vector<audit_ingest::parsed_audit_event> events;
		std::string parse_error;
		const unsigned long long parse_start_ns = COLLECTOR_TIMING_NOW();
		bool parse_ok = audit_ingest::parse_audit_records(records.data(), records.size(), &events, &parse_error);
		[[maybe_unused]] const unsigned long long parse_ns = COLLECTOR_TIMING_NOW() - parse_start_ns;
		if (!parse_ok) {
			reply->set_ok(false);
			reply->set_message("invalid audit records: " + parse_error);
			return grpc::Status::OK;
		}
		if (request->record_count() != events.size()) {
			reply->set_ok(false);
			reply->set_message("record_count mismatch");
			return grpc::Status::OK;
		}
#if AUDIT_PERF_FIELDS_ENABLED
		unsigned long long collector_receive_ns = monotonic_ns();
		for (const auto &parsed : events)
			const_cast<event *>(parsed.record)->perf_collector_receive_ns = collector_receive_ns;
#endif
		if (mongo_sink_ && mongo_sink_->enabled()) {
			std::string task_records(records.data(), records.size());
			auto task = std::make_shared<MongoInsertTask>(request->agent_id(), request->server_ip(),
								     std::move(task_records), events);
			if (!mongo_workers_ || !mongo_workers_->submit(task)) {
				reply->set_ok(false);
				reply->set_message("mongodb insert queue is closed");
				return grpc::Status::OK;
			}
			mongo_insert_result result = task->wait();
			if (!result.ok) {
				reply->set_ok(false);
				reply->set_message("mongodb insert failed: " + result.error);
				return grpc::Status::OK;
			}
			reply->set_ok(true);
			reply->set_message("ok");
			reply->set_accepted_records(result.accepted_records);
			reply->set_accepted_bytes(result.accepted_bytes);
			{
				std::lock_guard<std::mutex> lock(counters_mutex_);
				accepted_records_ += result.accepted_records;
				accepted_bytes_ += result.accepted_bytes;
			}
#if AUDIT_GRPC_TIMING_ENABLED
			const unsigned long long upload_total_ns = collector_timing_now_ns() - upload_start_ns;
			record_collector_timing(collector_id_, listen_addr_, result.accepted_records, result.accepted_bytes,
						parse_ns, result.stats, upload_total_ns);
#endif
			return grpc::Status::OK;
		}
		if (!records.empty()) {
			size_t written = fwrite(records.data(), 1, records.size(), file_);
			fflush(file_);
			if (written != records.size()) {
				reply->set_ok(false);
				reply->set_message(strerror(errno));
				return grpc::Status::OK;
			}
		}
		reply->set_ok(true);
		reply->set_message("ok");
		reply->set_accepted_records(request->record_count());
		reply->set_accepted_bytes(records.size());
		{
			std::lock_guard<std::mutex> lock(counters_mutex_);
			accepted_records_ += request->record_count();
			accepted_bytes_ += records.size();
		}
		return grpc::Status::OK;
	}

private:
	FILE *file_ = nullptr;
	MongoSink *mongo_sink_ = nullptr;
	MongoInsertWorkerPool *mongo_workers_ = nullptr;
	std::string collector_id_;
	std::string listen_addr_;
	std::mutex counters_mutex_;
	unsigned long long accepted_records_ = 0;
	unsigned long long accepted_bytes_ = 0;
};

struct collector_app_config {
	std::string listen_addr = "0.0.0.0:50051";
	std::string storage = "local";
	bool registry_enabled = false;
	collector_registry_config registry;
	mongodb_config mongodb;
};

static bool load_config_file(const char *path, collector_app_config *config)
{
	if (!path || !*path || !config)
		return false;

	SimpleYaml yaml;
	if (!yaml.load(path))
		return false;

	// 运行时只读取部署脚本生成的 collector.yaml。部署层负责 global/node/override 合并。
	config->listen_addr = yaml.get_string("collector.listen_addr", config->listen_addr);
	config->storage = yaml.get_string("storage.type", config->storage);
	config->registry_enabled = yaml.get_bool("collector.registry.enabled", config->registry_enabled);
	config->registry.etcd_endpoint = yaml.get_string("collector.registry.etcd_endpoints", config->registry.etcd_endpoint);
	config->registry.service_name = yaml.get_string("collector.registry.service_name", config->registry.service_name);
	config->registry.collector_id = yaml.get_string("collector.registry.instance_id", config->registry.collector_id);
	config->registry.advertise_addr = yaml.get_string("collector.registry.advertise_addr", config->registry.advertise_addr);
	config->registry.lease_ttl_sec = yaml.get_u32("collector.registry.lease_ttl_sec", config->registry.lease_ttl_sec);
	config->registry.keepalive_interval_sec = yaml.get_u32("collector.registry.keepalive_interval_sec", config->registry.keepalive_interval_sec);
	config->mongodb.uri = yaml.get_string("mongodb.uri", config->mongodb.uri);
	config->mongodb.database = yaml.get_string("mongodb.database", config->mongodb.database);
	config->mongodb.collection = yaml.get_string("mongodb.collection", config->mongodb.collection);
	config->mongodb.schema_collection = yaml.get_string("mongodb.schema_collection", config->mongodb.schema_collection);
	config->mongodb.schema_file_path = yaml.get_string("mongodb.schema_file_path", config->mongodb.schema_file_path);
	config->mongodb.app_name = yaml.get_string("mongodb.app_name", config->mongodb.app_name);
	config->mongodb.write_concern = yaml.get_string("mongodb.write_concern", config->mongodb.write_concern);
	config->mongodb.write_concern_wtimeout_ms = yaml.get_u32("mongodb.write_concern_wtimeout_ms", config->mongodb.write_concern_wtimeout_ms);
	config->mongodb.connect_timeout_ms = yaml.get_u32("mongodb.connect_timeout_ms", config->mongodb.connect_timeout_ms);
	config->mongodb.server_selection_timeout_ms = yaml.get_u32("mongodb.server_selection_timeout_ms", config->mongodb.server_selection_timeout_ms);
	config->mongodb.socket_timeout_ms = yaml.get_u32("mongodb.socket_timeout_ms", config->mongodb.socket_timeout_ms);
	config->mongodb.pool_min_size = yaml.get_u32("mongodb.pool_min_size", config->mongodb.pool_min_size);
	config->mongodb.pool_max_size = yaml.get_u32("mongodb.pool_max_size", config->mongodb.pool_max_size);
	config->mongodb.insert_concurrency = yaml.get_u32("mongodb.insert_concurrency", config->mongodb.insert_concurrency);
	config->mongodb.worker_count = yaml.get_u32("mongodb.worker_count", config->mongodb.worker_count);
	config->mongodb.queue_capacity = yaml.get_u32("mongodb.queue_capacity", config->mongodb.queue_capacity);
	config->mongodb.bulk_max_records = yaml.get_u32("mongodb.bulk_max_records", config->mongodb.bulk_max_records);
	config->mongodb.bulk_max_bytes = yaml.get_u32("mongodb.bulk_max_bytes", config->mongodb.bulk_max_bytes);
	config->mongodb.ordered_insert = yaml.get_bool("mongodb.ordered_insert", config->mongodb.ordered_insert);
	return true;
}

static const char *config_path_from_args(int argc, char **argv)
{
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--config") == 0)
			return argv[i + 1];
	}
	return "collector.yaml";
}

int main(int argc, char **argv)
{
	collector_app_config config;
	const char *config_path = config_path_from_args(argc, argv);
	load_config_file(config_path, &config);
	const char *output_path = "collector_events.adt";

	MongoSink mongo_sink;
	std::unique_ptr<MongoInsertWorkerPool> mongo_workers;
	if (config.storage == "mongodb") {
		std::string error;
		if (!mongo_sink.start(config.mongodb, &error)) {
			fprintf(stderr, "collector MongoDB startup failed: %s\n", error.c_str());
			return 1;
		}
		unsigned int worker_count = config.mongodb.worker_count ? config.mongodb.worker_count : config.mongodb.insert_concurrency;
		if (worker_count == 0)
			worker_count = 1;
		mongo_workers.reset(new MongoInsertWorkerPool(&mongo_sink, worker_count, config.mongodb.queue_capacity));
		if (!mongo_workers->start()) {
			fprintf(stderr, "collector MongoDB worker startup failed\n");
			return 1;
		}
		printf("collector mongodb uri=%s database=%s collection=%s workers=%u queue_capacity=%u\n",
		       config.mongodb.uri.c_str(), config.mongodb.database.c_str(), config.mongodb.collection.c_str(),
		       worker_count, config.mongodb.queue_capacity);
	}
	AuditCollectorService service(output_path, config.storage == "mongodb" ? &mongo_sink : nullptr,
				      mongo_workers.get(), config.registry.collector_id, config.listen_addr);
	CollectorRegistry registry;
	if (config.registry_enabled && !registry.start(config.registry)) {
		fprintf(stderr, "collector etcd registration failed; collector will not start\n");
		return 1;
	}
	grpc::ServerBuilder builder;
	builder.AddListeningPort(config.listen_addr, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	if (!server) {
		fprintf(stderr, "Failed to listen on %s\n", config.listen_addr.c_str());
		return 1;
	}
	printf("collector listen=%s storage=%s output=%s config=%s\n", config.listen_addr.c_str(), config.storage.c_str(), output_path, config_path);
#if AUDIT_GRPC_TIMING_ENABLED
	collector_timing_log_enabled(config.registry.collector_id, config.listen_addr, config.storage, config_path);
#endif
	server->Wait();
	registry.stop();
	return 0;
}
