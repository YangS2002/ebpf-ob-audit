// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef LOCAL_IP_H
#define LOCAL_IP_H

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// 从 etcd 端点串解析出首个 host（用于选路探测本机源地址）。
// 支持 "http://ip:2379"、"ip:2379"、逗号分隔多端点，返回不含 scheme/port/path 的 host。
static inline std::string endpoint_host(const std::string &endpoint)
{
	std::string s = endpoint;
	std::string::size_type comma = s.find(',');
	if (comma != std::string::npos)
		s = s.substr(0, comma);
	std::string::size_type scheme = s.find("://");
	if (scheme != std::string::npos)
		s = s.substr(scheme + 3);
	std::string::size_type slash = s.find('/');
	if (slash != std::string::npos)
		s = s.substr(0, slash);
	std::string::size_type colon = s.rfind(':');
	if (colon != std::string::npos)
		s = s.substr(0, colon);
	return s;
}

// 探测本机出网 IPv4：对 peer_ip（优先）或公网哨兵地址做 UDP connect（不发包），
// 再 getsockname 取内核为该目的地选择的源地址。失败返回空串。
static inline std::string detect_local_ipv4(const std::string &peer_ip = "")
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	if (peer_ip.empty() || inet_pton(AF_INET, peer_ip.c_str(), &addr.sin_addr) != 1)
		inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return "";
	std::string ip;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		struct sockaddr_in local;
		memset(&local, 0, sizeof(local));
		socklen_t len = sizeof(local);
		if (getsockname(fd, (struct sockaddr *)&local, &len) == 0) {
			char buf[INET_ADDRSTRLEN] = {};
			if (inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf)))
				ip.assign(buf);
		}
	}
	close(fd);
	return ip;
}

#endif /* LOCAL_IP_H */
