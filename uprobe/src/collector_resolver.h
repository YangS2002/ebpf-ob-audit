// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_RESOLVER_H
#define COLLECTOR_RESOLVER_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace grpc {
class ClientContext;
}

class CollectorResolver {
public:
	virtual ~CollectorResolver() = default;

	virtual bool start() = 0;
	virtual void stop() = 0;
	// Returns the current sorted set of collector "ip:port" addresses and, via
	// out-param, a version that increases only when the membership set changes.
	virtual std::vector<std::string> addresses(uint64_t *set_version) = 0;
};

class StaticCollectorResolver final : public CollectorResolver {
public:
	explicit StaticCollectorResolver(std::string addr);

	bool start() override;
	void stop() override;
	std::vector<std::string> addresses(uint64_t *set_version) override;

private:
	std::string addr_;
};

class EtcdCollectorResolver final : public CollectorResolver {
public:
	EtcdCollectorResolver(std::string endpoints, std::string service_name, std::string agent_id,
			      std::string policy, bool watch_enabled, uint32_t refresh_interval_ms,
			      uint32_t rebuild_debounce_ms);
	~EtcdCollectorResolver() override;

	bool start() override;
	void stop() override;
	std::vector<std::string> addresses(uint64_t *set_version) override;

private:
	// Holds the persistent etcd channel + KV/Watch stubs; opaque to keep the
	// generated gRPC headers out of this header (defined in the .cpp).
	struct EtcdConn;

	bool ensure_conn_locked();
	// Runs a one-shot Range using the persistent kv stub (no CreateChannel).
	// Fills out_list with the sorted deduped ip:port set and out_revision with
	// the etcd response revision. Returns false on RPC failure.
	bool do_range(std::vector<std::string> *out_list, int64_t *out_revision);
	// Diffs new_list against addresses_ and bumps set_version_ only if different.
	void apply_new_set(const std::vector<std::string> &new_list);
	void discovery_loop();

	std::string endpoints_;
	std::string service_name_;
	std::string agent_id_;
	std::string policy_; // deprecated: no longer used for selection (gRPC round_robin)
	bool watch_enabled_ = true;
	uint32_t refresh_interval_ms_ = 30000;
	uint32_t rebuild_debounce_ms_ = 300;

	std::unique_ptr<EtcdConn> conn_;

	std::mutex mutex_;
	std::condition_variable stop_cv_;
	std::vector<std::string> addresses_;
	uint64_t set_version_ = 0;
	int64_t revision_ = 0;
	std::atomic<bool> running_{false};
	std::thread worker_;
	// Client context for the in-flight watch stream, so stop() can TryCancel().
	std::mutex watch_ctx_mutex_;
	grpc::ClientContext *watch_ctx_ = nullptr;
};

#endif /* COLLECTOR_RESOLVER_H */
