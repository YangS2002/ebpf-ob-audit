// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_REGISTRY_H
#define COLLECTOR_REGISTRY_H

#include <cstdint>
#include <memory>
#include <string>

struct collector_registry_config {
	std::string collector_id;
	std::string service_name = "audit-collector";
	std::string advertise_addr;
	std::string etcd_endpoint;
	uint32_t lease_ttl_sec = 10;
	uint32_t keepalive_interval_sec = 3;
};

class CollectorRegistry {
public:
	CollectorRegistry();
	~CollectorRegistry();

	CollectorRegistry(const CollectorRegistry &) = delete;
	CollectorRegistry &operator=(const CollectorRegistry &) = delete;

	bool start(const collector_registry_config &config);
	void stop();
	bool enabled() const;

	struct Impl;

private:
	std::unique_ptr<Impl> impl_;
};

#endif /* COLLECTOR_REGISTRY_H */
