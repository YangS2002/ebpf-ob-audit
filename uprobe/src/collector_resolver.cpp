// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "collector_resolver.h"

#include <algorithm>
#include <chrono>
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

std::vector<std::string> StaticCollectorResolver::addresses(uint64_t *set_version)
{
	if (set_version)
		*set_version = 1;
	if (addr_.empty())
		return {};
	return {addr_};
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
	return std::string("\0", 1);
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

struct EtcdCollectorResolver::EtcdConn {
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<etcdserverpb::KV::Stub> kv_stub;
	std::unique_ptr<etcdserverpb::Watch::Stub> watch_stub;
};

EtcdCollectorResolver::EtcdCollectorResolver(std::string endpoints, std::string service_name,
					     std::string agent_id, std::string policy, bool watch_enabled,
					     uint32_t refresh_interval_ms, uint32_t rebuild_debounce_ms)
	: endpoints_(std::move(endpoints)), service_name_(std::move(service_name)),
	  agent_id_(std::move(agent_id)), policy_(std::move(policy)), watch_enabled_(watch_enabled),
	  refresh_interval_ms_(refresh_interval_ms ? refresh_interval_ms : 30000),
	  rebuild_debounce_ms_(rebuild_debounce_ms)
{
}

EtcdCollectorResolver::~EtcdCollectorResolver()
{
	stop();
}

bool EtcdCollectorResolver::ensure_conn_locked()
{
	if (conn_ && conn_->channel)
		return true;
	if (endpoints_.empty())
		return false;
	conn_.reset(new EtcdConn());
	conn_->channel = grpc::CreateChannel(first_endpoint(endpoints_), grpc::InsecureChannelCredentials());
	conn_->kv_stub = etcdserverpb::KV::NewStub(conn_->channel);
	conn_->watch_stub = etcdserverpb::Watch::NewStub(conn_->channel);
	return true;
}

bool EtcdCollectorResolver::do_range(std::vector<std::string> *out_list, int64_t *out_revision)
{
	if (!conn_ || !conn_->kv_stub)
		return false;
	std::string prefix = collectors_prefix(service_name_);
	etcdserverpb::RangeRequest request;
	request.set_key(prefix);
	request.set_range_end(prefix_end(prefix));
	etcdserverpb::RangeResponse response;
	grpc::ClientContext context;
	grpc::Status status = conn_->kv_stub->Range(&context, request, &response);
	if (!status.ok()) {
		fprintf(stderr, "etcd Range collectors failed: %s\n", status.error_message().c_str());
		return false;
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
	for (const auto &e : entries) {
		if (std::find(next.begin(), next.end(), e.addr) == next.end())
			next.push_back(e.addr);
	}
	if (out_list)
		*out_list = std::move(next);
	if (out_revision)
		*out_revision = response.header().revision();
	return true;
}

void EtcdCollectorResolver::apply_new_set(const std::vector<std::string> &new_list)
{
	std::vector<std::string> sorted = new_list;
	std::sort(sorted.begin(), sorted.end());
	if (sorted == addresses_)
		return;
	addresses_ = std::move(sorted);
	set_version_++;
	fprintf(stderr, "collector set changed: count=%zu set_version=%llu\n",
		addresses_.size(), (unsigned long long)set_version_);
}

bool EtcdCollectorResolver::start()
{
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (endpoints_.empty())
			return false;
		if (running_.load())
			return true;
		if (!ensure_conn_locked())
			return false;
		// Synchronous initial Range so the sender can build a channel immediately.
		std::vector<std::string> initial;
		int64_t revision = 0;
		if (do_range(&initial, &revision)) {
			apply_new_set(initial);
			revision_ = revision;
		}
		if (addresses_.empty())
			fprintf(stderr, "waiting for collector registration in etcd: service=%s\n",
				(service_name_.empty() ? "audit-collector" : service_name_.c_str()));
		running_.store(true);
	}
	worker_ = std::thread(&EtcdCollectorResolver::discovery_loop, this);
	return true;
}

void EtcdCollectorResolver::stop()
{
	bool was_running = running_.exchange(false);
	{
		std::lock_guard<std::mutex> lock(watch_ctx_mutex_);
		if (watch_ctx_)
			watch_ctx_->TryCancel();
	}
	stop_cv_.notify_all();
	if (worker_.joinable())
		worker_.join();
	if (!was_running)
		return;
	std::lock_guard<std::mutex> lock(mutex_);
	addresses_.clear();
	revision_ = 0;
	conn_.reset();
}

std::vector<std::string> EtcdCollectorResolver::addresses(uint64_t *set_version)
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (set_version)
		*set_version = set_version_;
	return addresses_;
}

void EtcdCollectorResolver::discovery_loop()
{
	while (running_.load()) {
		if (!watch_enabled_) {
			// Periodic Range only.
			{
				std::vector<std::string> list;
				int64_t revision = 0;
				std::lock_guard<std::mutex> lock(mutex_);
				if (ensure_conn_locked() && do_range(&list, &revision)) {
					apply_new_set(list);
					revision_ = revision;
				}
			}
			std::unique_lock<std::mutex> lock(mutex_);
			stop_cv_.wait_for(lock, std::chrono::milliseconds(refresh_interval_ms_),
					  [this] { return !running_.load(); });
			continue;
		}

		// Establish/refresh the set via Range and open a watch from the revision.
		int64_t start_revision = 0;
		{
			std::vector<std::string> list;
			int64_t revision = 0;
			std::lock_guard<std::mutex> lock(mutex_);
			if (!ensure_conn_locked()) {
				// Connection unavailable; back off and retry.
			} else if (do_range(&list, &revision)) {
				apply_new_set(list);
				revision_ = revision;
			}
			start_revision = revision_;
		}

		grpc::ClientContext context;
		{
			std::lock_guard<std::mutex> lock(watch_ctx_mutex_);
			watch_ctx_ = &context;
		}
		std::shared_ptr<etcdserverpb::Watch::Stub> watch_stub;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (conn_ && conn_->watch_stub)
				watch_stub = std::shared_ptr<etcdserverpb::Watch::Stub>(
					conn_->watch_stub.get(), [](etcdserverpb::Watch::Stub *) {});
		}
		bool need_resync = false;
		if (watch_stub && running_.load()) {
			auto stream = watch_stub->Watch(&context);
			std::string prefix = collectors_prefix(service_name_);
			etcdserverpb::WatchRequest req;
			auto *create = req.mutable_create_request();
			create->set_key(prefix);
			create->set_range_end(prefix_end(prefix));
			create->set_start_revision(start_revision + 1);
			if (!stream->Write(req)) {
				need_resync = true;
			} else {
				// Working copy of the current set for incremental apply.
				std::vector<std::string> working;
				{
					std::lock_guard<std::mutex> lock(mutex_);
					working = addresses_;
				}
				etcdserverpb::WatchResponse resp;
				while (running_.load() && stream->Read(&resp)) {
					if (resp.canceled() || resp.compact_revision() != 0) {
						need_resync = true;
						break;
					}
					if (resp.created() && resp.events_size() == 0)
						continue;
					bool changed = false;
					for (const auto &ev : resp.events()) {
						const auto &kvp = ev.kv();
						if (ev.type() == etcdserverpb::Event::DELETE) {
							std::string addr = json_string_value(kvp.value(), "address");
							// DELETE events may not carry value; match by re-Range fallback.
							if (addr.empty()) {
								need_resync = true;
								changed = false;
								break;
							}
							auto it = std::find(working.begin(), working.end(), addr);
							if (it != working.end()) {
								working.erase(it);
								changed = true;
							}
						} else {
							std::string addr = json_string_value(kvp.value(), "address");
							std::string host = json_string_value(kvp.value(), "host");
							std::string protocol = json_string_value(kvp.value(), "protocol");
							if (addr.empty() || host.empty() || protocol.empty())
								continue;
							if (std::find(working.begin(), working.end(), addr) == working.end()) {
								working.push_back(addr);
								changed = true;
							}
						}
						if (resp.header().revision() != 0)
							start_revision = resp.header().revision();
					}
					if (need_resync)
						break;
					if (changed) {
						// Debounce: give a short window for a burst to settle,
						// then apply once. Since Read blocks, sleep briefly.
						if (rebuild_debounce_ms_ > 0)
							std::this_thread::sleep_for(
								std::chrono::milliseconds(rebuild_debounce_ms_));
						std::lock_guard<std::mutex> lock(mutex_);
						apply_new_set(working);
						if (start_revision > revision_)
							revision_ = start_revision;
					}
				}
			}
			context.TryCancel();
			stream->Finish();
		}
		{
			std::lock_guard<std::mutex> lock(watch_ctx_mutex_);
			watch_ctx_ = nullptr;
		}

		if (!running_.load())
			break;
		// On watch end/error, wait a bounded interval (also the periodic-Range
		// fallback cadence) before resyncing and reopening the watch.
		uint32_t wait_ms = need_resync ? 200 : refresh_interval_ms_;
		std::unique_lock<std::mutex> lock(mutex_);
		stop_cv_.wait_for(lock, std::chrono::milliseconds(wait_ms),
				  [this] { return !running_.load(); });
	}
}


