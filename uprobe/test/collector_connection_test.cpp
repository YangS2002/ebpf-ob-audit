// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <netdb.h>
#include <string>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "etcdserverpb/rpc.grpc.pb.h"

struct test_config {
	std::string etcd_endpoint = "http://7.27.43.139:2379";
	std::string service_name = "audit-collector";
};

struct collector_entry {
	std::string key;
	std::string address;
};

static std::string trim(std::string value)
{
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
		value.erase(value.begin());
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
		value.pop_back();
	return value;
}

static bool load_config(const char *path, test_config *config)
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
		if (key == "collector_discovery_etcd_endpoints")
			config->etcd_endpoint = value;
		else if (key == "collector_discovery_service_name")
			config->service_name = value;
	}
	fclose(file);
	return true;
}

static std::string first_endpoint(std::string endpoints)
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
	for (int i = static_cast<int>(end.size()) - 1; i >= 0; --i) {
		if (static_cast<unsigned char>(end[static_cast<size_t>(i)]) != 0xff) {
			end[static_cast<size_t>(i)]++;
			end.resize(static_cast<size_t>(i) + 1);
			return end;
		}
	}
	return "\0";
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

static bool split_host_port(const std::string &address, std::string *host, std::string *port)
{
	size_t pos = address.rfind(':');
	if (pos == std::string::npos || pos == 0 || pos + 1 >= address.size())
		return false;
	*host = address.substr(0, pos);
	*port = address.substr(pos + 1);
	return true;
}

static bool tcp_connect(const std::string &address)
{
	std::string host;
	std::string port;
	if (!split_host_port(address, &host, &port)) {
		fprintf(stderr, "invalid collector address: %s\n", address.c_str());
		return false;
	}

	addrinfo hints = {};
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	addrinfo *result = nullptr;
	int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo failed: %s %s\n", address.c_str(), gai_strerror(ret));
		return false;
	}

	bool ok = false;
	for (addrinfo *rp = result; rp; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			ok = true;
		close(fd);
		if (ok)
			break;
	}
	freeaddrinfo(result);
	return ok;
}

static bool list_collectors(const test_config &config, std::vector<collector_entry> *collectors)
{
	std::string prefix = "/services/" + config.service_name + "/";
	auto channel = grpc::CreateChannel(first_endpoint(config.etcd_endpoint), grpc::InsecureChannelCredentials());
	auto kv = etcdserverpb::KV::NewStub(channel);

	etcdserverpb::RangeRequest request;
	request.set_key(prefix);
	request.set_range_end(prefix_end(prefix));
	etcdserverpb::RangeResponse response;
	grpc::ClientContext context;
	grpc::Status status = kv->Range(&context, request, &response);
	if (!status.ok()) {
		fprintf(stderr, "etcd range failed: endpoint=%s error=%s\n",
			config.etcd_endpoint.c_str(), status.error_message().c_str());
		return false;
	}

	for (const auto &kvp : response.kvs()) {
		std::string collector_id = json_string_value(kvp.value(), "collector_id");
		std::string address = json_string_value(kvp.value(), "address");
		std::string host = json_string_value(kvp.value(), "host");
		std::string protocol = json_string_value(kvp.value(), "protocol");
		if (collector_id.empty() || address.empty() || host.empty() || protocol.empty()) {
			fprintf(stderr, "skip invalid collector entry: key=%s\n", kvp.key().c_str());
			continue;
		}
		collectors->push_back({kvp.key(), address});
	}
	std::sort(collectors->begin(), collectors->end(), [](const collector_entry &a, const collector_entry &b) {
		return a.key < b.key;
	});
	return true;
}

static void print_hash_assignments(const std::vector<collector_entry> &collectors, int argc, char **argv)
{
	if (collectors.empty())
		return;
	std::hash<std::string> hasher;
	for (int i = 2; i < argc; i++) {
		std::string arg = argv[i];
		if (arg == "--agents")
			continue;
		size_t index = hasher(arg) % collectors.size();
		printf("agent=%s selected=%s %s index=%zu/%zu\n",
		       arg.c_str(), collectors[index].key.c_str(), collectors[index].address.c_str(), index, collectors.size());
	}
}

int main(int argc, char **argv)
{
	const char *config_path = argc >= 2 ? argv[1] : "uprobe/uprobe.conf";
	test_config config;
	if (!load_config(config_path, &config)) {
		fprintf(stderr, "failed to load config: %s\n", config_path);
		return 1;
	}

	printf("config=%s etcd=%s service=%s\n", config_path, config.etcd_endpoint.c_str(), config.service_name.c_str());
	std::vector<collector_entry> collectors;
	if (!list_collectors(config, &collectors))
		return 1;
	if (collectors.empty()) {
		fprintf(stderr, "no valid collectors found\n");
		return 1;
	}

	bool all_ok = true;
	for (const auto &collector : collectors) {
		bool ok = tcp_connect(collector.address);
		printf("%s %s tcp=%s\n", collector.key.c_str(), collector.address.c_str(), ok ? "OK" : "FAIL");
		all_ok = all_ok && ok;
	}
	print_hash_assignments(collectors, argc, argv);
	return all_ok ? 0 : 1;
}
