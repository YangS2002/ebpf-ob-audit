// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"
#include "audit_event_parser.h"
#include "collector_registry.h"
#include "mongodb_sink.h"
#include "uprobe.h"

#if AUDIT_PERF_FIELDS_ENABLED
static unsigned long long monotonic_ns()
{
	return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}
#endif

class AuditCollectorService final : public audit::AuditCollector::Service {
public:
	explicit AuditCollectorService(const std::string &output_path, MongoSink *mongo_sink = nullptr)
		: mongo_sink_(mongo_sink)
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
		if (!audit_ingest::parse_audit_records(records.data(), records.size(), &events, &parse_error)) {
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
			unsigned long long accepted_records = 0;
			unsigned long long accepted_bytes = 0;
			std::string mongo_error;
			if (!mongo_sink_->insert_events(request->agent_id(), request->server_ip(), events,
							   &accepted_records, &accepted_bytes, &mongo_error)) {
				reply->set_ok(false);
				reply->set_message("mongodb insert failed: " + mongo_error);
				return grpc::Status::OK;
			}
			reply->set_ok(true);
			reply->set_message("ok");
			reply->set_accepted_records(accepted_records);
			reply->set_accepted_bytes(accepted_bytes);
			accepted_records_ += accepted_records;
			accepted_bytes_ += accepted_bytes;
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
		accepted_records_ += request->record_count();
		accepted_bytes_ += records.size();
		return grpc::Status::OK;
	}

private:
	FILE *file_ = nullptr;
	MongoSink *mongo_sink_ = nullptr;
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

static std::string trim(std::string value)
{
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
		value.erase(value.begin());
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
		value.pop_back();
	return value;
}

static bool parse_bool(const std::string &value)
{
	return value == "true" || value == "1" || value == "yes";
}

static bool load_config_file(const char *path, collector_app_config *config)
{
	FILE *file = fopen(path, "r");
	if (!file)
		return false;

	char line[512];
	while (fgets(line, sizeof(line), file)) {
		std::string text = trim(line);
		if (text.empty() || text[0] == '#')
			continue;
		size_t pos = text.find('=');
		if (pos == std::string::npos)
			continue;
		std::string key = trim(text.substr(0, pos));
		std::string value = trim(text.substr(pos + 1));
			if (key == "collector_listen_addr")
				config->listen_addr = value;
			else if (key == "collector_storage")
				config->storage = value;
			else if (key == "collector_registry_enabled")
			config->registry_enabled = parse_bool(value);
		else if (key == "collector_registry_etcd_endpoints")
			config->registry.etcd_endpoint = value;
		else if (key == "collector_registry_service_name")
			config->registry.service_name = value;
		else if (key == "collector_registry_instance_id")
			config->registry.collector_id = value;
		else if (key == "collector_registry_advertise_addr")
			config->registry.advertise_addr = value;
		else if (key == "collector_registry_lease_ttl_sec")
			config->registry.lease_ttl_sec = static_cast<uint32_t>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "collector_registry_keepalive_interval_sec")
				config->registry.keepalive_interval_sec = static_cast<uint32_t>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_uri")
				config->mongodb.uri = value;
			else if (key == "mongodb_database")
				config->mongodb.database = value;
			else if (key == "mongodb_collection")
				config->mongodb.collection = value;
			else if (key == "mongodb_app_name")
				config->mongodb.app_name = value;
			else if (key == "mongodb_write_concern")
				config->mongodb.write_concern = value;
			else if (key == "mongodb_connect_timeout_ms")
				config->mongodb.connect_timeout_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_server_selection_timeout_ms")
				config->mongodb.server_selection_timeout_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_socket_timeout_ms")
				config->mongodb.socket_timeout_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_pool_min_size")
				config->mongodb.pool_min_size = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_pool_max_size")
				config->mongodb.pool_max_size = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_insert_concurrency")
				config->mongodb.insert_concurrency = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_bulk_max_records")
				config->mongodb.bulk_max_records = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_bulk_max_bytes")
				config->mongodb.bulk_max_bytes = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
			else if (key == "mongodb_ordered_insert")
				config->mongodb.ordered_insert = parse_bool(value);
	}
	fclose(file);
	return true;
}

static const char *config_path_from_args(int argc, char **argv)
{
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--config") == 0)
			return argv[i + 1];
	}
	return "uprobe.conf";
}

int main(int argc, char **argv)
{
	collector_app_config config;
	const char *config_path = config_path_from_args(argc, argv);
	load_config_file(config_path, &config);
	const char *output_path = "collector_events.adt";

	MongoSink mongo_sink;
	if (config.storage == "mongodb") {
		std::string error;
		if (!mongo_sink.start(config.mongodb, &error)) {
			fprintf(stderr, "collector MongoDB startup failed: %s\n", error.c_str());
			return 1;
		}
		printf("collector mongodb uri=%s database=%s collection=%s\n",
		       config.mongodb.uri.c_str(), config.mongodb.database.c_str(), config.mongodb.collection.c_str());
	}
	AuditCollectorService service(output_path, config.storage == "mongodb" ? &mongo_sink : nullptr);
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
	server->Wait();
	registry.stop();
	return 0;
}
