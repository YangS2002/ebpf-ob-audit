// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_resolver.h"

#include <algorithm>
#include <cstdio>
#include <utility>

#include <grpcpp/grpcpp.h>
#include "etcdserverpb/rpc.grpc.pb.h"

StaticCollectorResolver::StaticCollectorResolver(std::string addr) : addr_(std::move(addr))
{
}

bool StaticCollectorResolver::start()
{
	return !addr_.empty();
}

void StaticCollectorResolver::stop()
{
}

std::string StaticCollectorResolver::current()
{
	return addr_;
}

std::string StaticCollectorResolver::next()
{
	return addr_;
}

void StaticCollectorResolver::report_failure(const std::string &)
{
}

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

static std::string prefix_end(const std::string &prefix)
{
	std::string end = prefix;
	for (int i = (int)end.size() - 1; i >= 0; --i) {
		if ((unsigned char)end[(size_t)i] != 0xff) {
			end[(size_t)i]++;
			end.resize((size_t)i + 1);
			return end;
		}
	}
	return "\0";
}

static std::string collectors_prefix(const std::string &service_name)
{
	return "/services/" + (service_name.empty() ? "audit-collector" : service_name) + "/";
}

static std::string json_string_value(const std::string &json, const std::string &key)
{
	std::string pattern = "\"" + key + "\"";
	size_t pos = json.find(pattern);
	if (pos == std::string::npos)
		return "";
	pos = json.find(':', pos + pattern.size());
	if (pos == std::string::npos)
		return "";
	pos = json.find('"', pos);
	if (pos == std::string::npos)
		return "";
	pos++;
	std::string value;
	for (; pos < json.size(); pos++) {
		char c = json[pos];
		if (c == '"')
			break;
		if (c == '\\' && pos + 1 < json.size()) {
			value.push_back(json[pos + 1]);
			pos++;
		} else {
			value.push_back(c);
		}
	}
	return value;
}

EtcdCollectorResolver::EtcdCollectorResolver(std::string endpoints, std::string service_name,
					     std::string agent_id, std::string policy)
	: endpoints_(std::move(endpoints)), service_name_(std::move(service_name)), agent_id_(std::move(agent_id)),
	  policy_(std::move(policy))
{
}

bool EtcdCollectorResolver::start()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (endpoints_.empty())
		return false;
	started_ = true;
	if (refresh_locked())
		select_initial_locked();
	else
		fprintf(stderr, "waiting for collector registration in etcd: service=%s\n",
			(service_name_.empty() ? "audit-collector" : service_name_.c_str()));
	return true;
}

void EtcdCollectorResolver::stop()
{
	std::lock_guard<std::mutex> lock(mutex_);
	started_ = false;
	collectors_.clear();
	current_index_ = 0;
}

std::string EtcdCollectorResolver::current()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (collectors_.empty())
		refresh_locked();
	if (collectors_.empty())
		return "";
	if (current_index_ >= collectors_.size())
		current_index_ = 0;
	return collectors_[current_index_];
}

std::string EtcdCollectorResolver::next()
{
	std::lock_guard<std::mutex> lock(mutex_);
	refresh_locked();
	if (collectors_.empty())
		return "";
	current_index_ = (current_index_ + 1) % collectors_.size();
	return collectors_[current_index_];
}

void EtcdCollectorResolver::report_failure(const std::string &addr)
{
	fprintf(stderr, "collector failure reported: %s\n", addr.c_str());
}

bool EtcdCollectorResolver::refresh_locked()
{
	if (endpoints_.empty())
		return false;
	std::string prefix = collectors_prefix(service_name_);
	std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(first_endpoint(endpoints_), grpc::InsecureChannelCredentials());
	std::unique_ptr<etcdserverpb::KV::Stub> kv = etcdserverpb::KV::NewStub(channel);
	etcdserverpb::RangeRequest request;
	request.set_key(prefix);
	request.set_range_end(prefix_end(prefix));
	etcdserverpb::RangeResponse response;
	grpc::ClientContext context;
	grpc::Status status = kv->Range(&context, request, &response);
	if (!status.ok()) {
		fprintf(stderr, "etcd Range collectors failed: %s\n", status.error_message().c_str());
		return !collectors_.empty();
	}

	struct entry {
		std::string key;
		std::string addr;
	};
	std::vector<entry> entries;
	for (const auto &kvp : response.kvs()) {
		std::string addr = json_string_value(kvp.value(), "address");
		std::string host = json_string_value(kvp.value(), "host");
		std::string protocol = json_string_value(kvp.value(), "protocol");
		if (addr.empty() || host.empty() || protocol.empty()) {
			fprintf(stderr, "skip invalid collector registry entry: key=%s\n", kvp.key().c_str());
			continue;
		}
		entries.push_back({kvp.key(), addr});
	}
	std::sort(entries.begin(), entries.end(), [](const entry &a, const entry &b) { return a.key < b.key; });
	std::vector<std::string> next;
	for (const auto &entry : entries)
		next.push_back(entry.addr);
	if (next.empty()) {
		collectors_.clear();
		current_index_ = 0;
		return false;
	}
	std::string old = collectors_.empty() || current_index_ >= collectors_.size() ? "" : collectors_[current_index_];
	collectors_ = std::move(next);
	if (!old.empty()) {
		auto it = std::find(collectors_.begin(), collectors_.end(), old);
		if (it != collectors_.end())
			current_index_ = (size_t)std::distance(collectors_.begin(), it);
		else
			current_index_ = 0;
	}
	return true;
}

void EtcdCollectorResolver::select_initial_locked()
{
	if (collectors_.empty())
		return;
	current_index_ = 0;
}
