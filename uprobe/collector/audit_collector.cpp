// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"
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

int main(int argc, char **argv)
{
	const char *listen_addr = argc >= 2 ? argv[1] : "0.0.0.0:50051";
	const char *output_path = argc >= 3 ? argv[2] : "collector_events.adt";

	AuditCollectorService service(output_path);
	grpc::ServerBuilder builder;
	builder.AddListeningPort(listen_addr, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	if (!server) {
		fprintf(stderr, "Failed to listen on %s\n", listen_addr);
		return 1;
	}
	printf("collector listen=%s output=%s\n", listen_addr, output_path);
	server->Wait();
	return 0;
}
