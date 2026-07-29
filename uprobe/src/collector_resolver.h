// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_RESOLVER_H
#define COLLECTOR_RESOLVER_H

#include <mutex>
#include <string>
#include <vector>

class CollectorResolver {
public:
	virtual ~CollectorResolver() = default;

	virtual bool start() = 0;
	virtual void stop() = 0;
	virtual std::string current() = 0;
	virtual std::string next() = 0;
	virtual void report_failure(const std::string &addr) = 0;
};

class StaticCollectorResolver final : public CollectorResolver {
public:
	explicit StaticCollectorResolver(std::string addr);

	bool start() override;
	void stop() override;
	std::string current() override;
	std::string next() override;
	void report_failure(const std::string &addr) override;

private:
	std::string addr_;
};

class EtcdCollectorResolver final : public CollectorResolver {
public:
	EtcdCollectorResolver(std::string endpoints, std::string service_name, std::string agent_id, std::string policy);

	bool start() override;
	void stop() override;
	std::string current() override;
	std::string next() override;
	void report_failure(const std::string &addr) override;

private:
	bool refresh_locked();
	void select_initial_locked();

	std::string endpoints_;
	std::string service_name_;
	std::string agent_id_;
	std::string policy_;
	std::vector<std::string> collectors_;
	size_t current_index_ = 0;
	bool started_ = false;
	std::mutex mutex_;
};

#endif /* COLLECTOR_RESOLVER_H */
