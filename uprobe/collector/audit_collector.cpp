// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"
#include "collector_registry.h"
#include "uprobe.h"

class AuditCollectorService final : public audit::AuditCollector::Service {
public:
	explicit AuditCollectorService(const std::string &output_path)
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
		const std::string &records = request->records();
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
	unsigned long long accepted_records_ = 0;
	unsigned long long accepted_bytes_ = 0;
};

struct collector_app_config {
	std::string listen_addr = "0.0.0.0:50051";
	bool registry_enabled = false;
	collector_registry_config registry;
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

	AuditCollectorService service(output_path);
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
	printf("collector listen=%s output=%s config=%s\n", config.listen_addr.c_str(), output_path, config_path);
	server->Wait();
	registry.stop();
	return 0;
}
