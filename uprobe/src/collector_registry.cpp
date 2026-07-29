// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_registry.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include <grpcpp/grpcpp.h>
#include "etcdserverpb/rpc.grpc.pb.h"

struct CollectorRegistry::Impl {
	bool enabled = false;
	bool stopping = false;
	collector_registry_config config;
	int64_t lease_id = 0;
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<etcdserverpb::KV::Stub> kv;
	std::unique_ptr<etcdserverpb::Lease::Stub> lease;
	std::thread worker;
	mutable std::mutex mutex;
};

static std::string first_endpoint(const std::string &endpoints)
{
	size_t pos = endpoints.find(',');
	std::string endpoint = pos == std::string::npos ? endpoints : endpoints.substr(0, pos);
	if (endpoint.rfind("http://", 0) == 0)
		endpoint = endpoint.substr(7);
	else if (endpoint.rfind("https://", 0) == 0)
		endpoint = endpoint.substr(8);
	return endpoint;
}

static std::string json_escape(const std::string &value)
{
	std::string out;
	for (char c : value) {
		switch (c) {
		case '\\': out += "\\\\"; break;
		case '"': out += "\\\""; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default: out += c; break;
		}
	}
	return out;
}

static std::string collector_key(const collector_registry_config &config)
{
	return "/services/" + config.service_name + "/" + config.collector_id;
}

static bool split_host_port(const std::string &addr, std::string *host, uint32_t *port)
{
	size_t pos = addr.rfind(':');
	if (pos == std::string::npos || pos == 0 || pos + 1 >= addr.size())
		return false;
	*host = addr.substr(0, pos);
	*port = static_cast<uint32_t>(strtoul(addr.substr(pos + 1).c_str(), nullptr, 10));
	return *port != 0;
}

static std::string collector_value(const collector_registry_config &config)
{
	std::string host;
	uint32_t port = 0;
	split_host_port(config.advertise_addr, &host, &port);
	std::ostringstream out;
	out << "{"
	    << "\"collector_id\":\"" << json_escape(config.collector_id) << "\","
	    << "\"address\":\"" << json_escape(config.advertise_addr) << "\","
	    << "\"host\":\"" << json_escape(host) << "\","
	    << "\"port\":" << port << ","
	    << "\"protocol\":\"grpc\","
	    << "\"start_time_unix_ms\":" << (long long)time(nullptr) * 1000
	    << "}";
	return out.str();
}

static bool grant_lease(CollectorRegistry::Impl *impl)
{
	etcdserverpb::LeaseGrantRequest request;
	request.set_ttl(impl->config.lease_ttl_sec ? impl->config.lease_ttl_sec : 10);
	etcdserverpb::LeaseGrantResponse response;
	grpc::ClientContext context;
	grpc::Status status = impl->lease->LeaseGrant(&context, request, &response);
	if (!status.ok() || !response.error().empty()) {
		fprintf(stderr, "collector etcd LeaseGrant failed: %s %s\n",
			status.error_message().c_str(), response.error().c_str());
		return false;
	}
	impl->lease_id = response.id();
	return impl->lease_id != 0;
}

static bool put_key(CollectorRegistry::Impl *impl)
{
	etcdserverpb::PutRequest request;
	request.set_key(collector_key(impl->config));
	request.set_value(collector_value(impl->config));
	request.set_lease(impl->lease_id);
	etcdserverpb::PutResponse response;
	grpc::ClientContext context;
	grpc::Status status = impl->kv->Put(&context, request, &response);
	if (!status.ok()) {
		fprintf(stderr, "collector etcd Put failed: %s\n", status.error_message().c_str());
		return false;
	}
	return true;
}

static void revoke_lease(CollectorRegistry::Impl *impl)
{
	if (impl->lease_id == 0 || !impl->lease)
		return;
	etcdserverpb::LeaseRevokeRequest request;
	request.set_id(impl->lease_id);
	etcdserverpb::LeaseRevokeResponse response;
	grpc::ClientContext context;
	impl->lease->LeaseRevoke(&context, request, &response);
	impl->lease_id = 0;
}

static void registry_worker(CollectorRegistry::Impl *impl)
{
	uint32_t interval = impl->config.keepalive_interval_sec ? impl->config.keepalive_interval_sec : 3;
	while (true) {
		{
			std::lock_guard<std::mutex> lock(impl->mutex);
			if (impl->stopping)
				break;
		}

		grpc::ClientContext context;
		std::shared_ptr<grpc::ClientReaderWriter<etcdserverpb::LeaseKeepAliveRequest,
			etcdserverpb::LeaseKeepAliveResponse>> stream(impl->lease->LeaseKeepAlive(&context));
		etcdserverpb::LeaseKeepAliveRequest request;
		request.set_id(impl->lease_id);
		if (!stream->Write(request)) {
			fprintf(stderr, "collector etcd LeaseKeepAlive write failed: lease=%lld\n", (long long)impl->lease_id);
		} else {
			etcdserverpb::LeaseKeepAliveResponse response;
			if (!stream->Read(&response))
				fprintf(stderr, "collector etcd LeaseKeepAlive read failed: lease=%lld\n", (long long)impl->lease_id);
		}
		stream->WritesDone();
		grpc::Status status = stream->Finish();
		if (!status.ok())
			fprintf(stderr, "collector etcd LeaseKeepAlive failed: %s\n", status.error_message().c_str());
		std::this_thread::sleep_for(std::chrono::seconds(interval));
	}
}

CollectorRegistry::CollectorRegistry() : impl_(new Impl)
{
}

CollectorRegistry::~CollectorRegistry()
{
	stop();
}

bool CollectorRegistry::start(const collector_registry_config &config)
{
	stop();
	if (config.etcd_endpoint.empty()) {
		fprintf(stderr, "collector registry config invalid: collector_registry_etcd_endpoints is empty\n");
		return false;
	}
	if (config.service_name.empty() || config.collector_id.empty() || config.advertise_addr.empty()) {
		fprintf(stderr, "collector registry config invalid: service name, instance id, or advertise address is empty\n");
		return false;
	}
	if (config.lease_ttl_sec <= config.keepalive_interval_sec) {
		fprintf(stderr, "collector registry config invalid: lease_ttl_sec must be greater than keepalive_interval_sec\n");
		return false;
	}
	impl_->config = config;
	impl_->config.lease_ttl_sec = impl_->config.lease_ttl_sec ? impl_->config.lease_ttl_sec : 10;
	impl_->config.keepalive_interval_sec = impl_->config.keepalive_interval_sec ? impl_->config.keepalive_interval_sec : 3;
	impl_->stopping = false;
	impl_->channel = grpc::CreateChannel(first_endpoint(impl_->config.etcd_endpoint), grpc::InsecureChannelCredentials());
	impl_->kv = etcdserverpb::KV::NewStub(impl_->channel);
	impl_->lease = etcdserverpb::Lease::NewStub(impl_->channel);
	if (!grant_lease(impl_.get()))
		return false;
	if (!put_key(impl_.get())) {
		revoke_lease(impl_.get());
		return false;
	}
	impl_->enabled = true;
	impl_->worker = std::thread(registry_worker, impl_.get());
	fprintf(stderr, "collector registered to etcd: key=%s addr=%s lease=%lld\n",
		collector_key(impl_->config).c_str(), impl_->config.advertise_addr.c_str(), (long long)impl_->lease_id);
	return true;
}

void CollectorRegistry::stop()
{
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		if (!impl_->enabled && !impl_->worker.joinable())
			return;
		impl_->stopping = true;
	}
	if (impl_->worker.joinable())
		impl_->worker.join();
	revoke_lease(impl_.get());
	impl_->enabled = false;
}

bool CollectorRegistry::enabled() const
{
	std::lock_guard<std::mutex> lock(impl_->mutex);
	return impl_->enabled;
}
