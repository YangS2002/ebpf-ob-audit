// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <csignal>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>

// libbpf 和 skeleton 是 C 接口，C++ 编译时需要保持 C linkage。
extern "C" {
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
}

#include "uprobe.h"
#include "audit_grpc_sender.h"
#include "ring_buffer/ring_buffer.h"

// pending 环形缓冲区容量。单条合并事件最大约 128KB(sql + params 各 64KB)。
#define PENDING_RINGBUF_SIZE (16 * 1024 * 1024)

static volatile bool exiting = false;

struct app_config {
	std::string agent_id;
	std::string server_ip_text;
	std::string collector_addr;
	std::string collector_discovery_etcd_endpoints;
	std::string collector_discovery_service_name;
	std::string collector_discovery_selection_policy;
	bool collector_discovery = false;
	unsigned int grpc_batch_bytes = 0;
	unsigned int grpc_timeout_ms = 0;
	unsigned long long grpc_queue_bytes = 0;
	unsigned int grpc_retry_initial_ms = 0;
	unsigned int grpc_retry_max_ms = 0;
};

struct writer_state {
	VarlenRingBuffer<unsigned long long> pending{PENDING_RINGBUF_SIZE};
	unsigned long long consumed_events = 0;
	unsigned long long consumed_bytes = 0;
	unsigned long long dropped_events = 0;
	char server_ip[MAX_IP_LEN] = {};
	AuditGrpcSender grpc;
};

static void handle_signal(int)
{
	exiting = true;
}

static void fill_ob_addr_ipv4(char *dst, const void *addr)
{
	int version = 4;
	unsigned int ip = ntohl(reinterpret_cast<const sockaddr_in *>(addr)->sin_addr.s_addr);
	std::memset(dst, 0, MAX_IP_LEN);
	std::memcpy(dst + OB_ADDR_VERSION_OFF, &version, sizeof(version));
	std::memcpy(dst + OB_ADDR_IP_OFF, &ip, sizeof(ip));
}

static bool fill_ipv4_string(char *dst, const char *ip)
{
	if (!ip || !*ip)
		return false;

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
		return false;
	fill_ob_addr_ipv4(dst, &addr);
	return true;
}

static std::string trim(std::string value)
{
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
		value.erase(value.begin());
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
		value.pop_back();
	return value;
}

static bool load_config(const char *path, app_config *config)
{
	if (!path || !*path)
		return false;
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
		if (key == "server_ip")
			config->server_ip_text = value;
		else if (key == "agent_id")
			config->agent_id = value;
		else if (key == "collector_addr")
			config->collector_addr = value;
		else if (key == "collector_discovery_enabled")
			config->collector_discovery = value == "true" || value == "1" || value == "yes";
		else if (key == "collector_discovery_etcd_endpoints")
			config->collector_discovery_etcd_endpoints = value;
		else if (key == "collector_discovery_service_name")
			config->collector_discovery_service_name = value;
		else if (key == "collector_discovery_selection_policy")
			config->collector_discovery_selection_policy = value;
		else if (key == "grpc_batch_bytes")
			config->grpc_batch_bytes = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
		else if (key == "grpc_timeout_ms")
			config->grpc_timeout_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
		else if (key == "grpc_queue_bytes")
			config->grpc_queue_bytes = strtoull(value.c_str(), nullptr, 10);
		else if (key == "grpc_retry_initial_ms")
			config->grpc_retry_initial_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
		else if (key == "grpc_retry_max_ms")
			config->grpc_retry_max_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
	}
	fclose(file);
	return true;
}

static void init_grpc_sender(AuditGrpcSender *sender, const app_config &config)
{
	audit_grpc_config grpc_config;
	grpc_config.agent_id = config.agent_id.empty() ? "default-agent" : config.agent_id;
	grpc_config.server_ip = config.server_ip_text;
	grpc_config.collector_addr = config.collector_addr;
	grpc_config.file_version = AUDIT_FILE_VERSION;
	grpc_config.event_size = sizeof(event);
	grpc_config.batch_bytes = config.grpc_batch_bytes;
	grpc_config.timeout_ms = config.grpc_timeout_ms;
	grpc_config.queue_bytes = config.grpc_queue_bytes;
	grpc_config.retry_initial_ms = config.grpc_retry_initial_ms;
	grpc_config.retry_max_ms = config.grpc_retry_max_ms;
	if (config.collector_discovery && !config.collector_discovery_etcd_endpoints.empty()) {
		std::unique_ptr<CollectorResolver> resolver(new EtcdCollectorResolver(
			config.collector_discovery_etcd_endpoints,
			config.collector_discovery_service_name.empty() ? "audit-collector" : config.collector_discovery_service_name,
			grpc_config.agent_id,
			config.collector_discovery_selection_policy.empty() ? "first" : config.collector_discovery_selection_policy));
		sender->start(grpc_config, std::move(resolver));
		return;
	}
	sender->start(grpc_config);
}

static void print_startup_status(const char *target, unsigned long long offset,
					 const char *config_file, const app_config &config, const writer_state &state)
{
	printf("uprobe config=%s target=%s offset=0x%llx\n", config_file, target, offset);
	printf("agent_id=%s server_ip=%s grpc_batch_bytes=%u grpc_timeout_ms=%u grpc_queue_bytes=%llu discovery=%s\n",
	       config.agent_id.empty() ? "default-agent" : config.agent_id.c_str(),
	       config.server_ip_text.empty() ? "<empty>" : config.server_ip_text.c_str(),
	       config.grpc_batch_bytes ? config.grpc_batch_bytes : 262144,
	       config.grpc_timeout_ms ? config.grpc_timeout_ms : 2000,
	       config.grpc_queue_bytes ? config.grpc_queue_bytes : 64ULL * 1024 * 1024,
	       config.collector_discovery ? "true" : "false");
	if (!state.grpc.enabled()) {
		printf("grpc upload disabled: no collector available\n");
		return;
	}

	printf("grpc collector discovery=%s target=%s connecting...\n",
	       config.collector_discovery ? "etcd" : "static", config.collector_addr.c_str());
	bool ready = state.grpc.wait_ready(config.grpc_timeout_ms ? config.grpc_timeout_ms : 2000);
	printf("grpc collector state=%s\n", ready ? "READY" : "NOT_READY");
	if (!ready)
		fprintf(stderr, "grpc collector not ready now; events will still be captured locally, upload attempts use timeout.\n");
}

static unsigned int clamp_capture(unsigned int len, unsigned int max_len)
{
	return len > max_len ? max_len : len;
}

static unsigned int event_names_len(const event *e)
{
	return e->user_name_len + e->proxy_user_name_len + e->tenant_name_len + e->db_name_len;
}

// 变长落地：所有数据经 grpc 发送，不写盘。
static int emit_record(writer_state *state, const char *data, size_t size)
{
	if (!state->grpc.submit(data, size)) {
		state->dropped_events++;
		return 0;
	}
	state->consumed_events++;
	state->consumed_bytes += size;
	return 0;
}

// 未分片小事件：值拷贝一份填 server_ip 再发。
static int append_event(writer_state *state, const event &e)
{
	if (!event_compact_size_valid(&e))
		return 0;
	event out = e;
	std::memcpy(out.server_ip, state->server_ip, sizeof(out.server_ip));
	return emit_record(state, reinterpret_cast<const char *>(&out), out.total_size);
}

// 合并完成的变长事件：段可写，直接在段头填 server_ip 再发。
static int append_merged(writer_state *state, char *seg, size_t size)
{
	event *hdr = reinterpret_cast<event *>(seg);
	std::memcpy(hdr->server_ip, state->server_ip, sizeof(hdr->server_ip));
	return emit_record(state, seg, size);
}

static int handle_main_event(writer_state *state, const event *e)
{
	if (!event_compact_size_valid(e))
		return 0;
	if ((e->fragment_flags & (FRAG_QUERY_SQL_FRAGMENTED | FRAG_PARAMS_VALUE_FRAGMENTED)) == 0)
		return append_event(state, *e);

	// 分片事件：按完整长度在 pending 环形缓冲区预分配整段。
	// 未分片字段用其首片长，分片字段用捕获上限 clamp 后的完整长。
	unsigned int names_len = event_names_len(e);
	unsigned int full_sql = (e->fragment_flags & FRAG_QUERY_SQL_FRAGMENTED)
					? clamp_capture(e->query_sql_len, AUDIT_SQL_CAPTURE_MAX)
					: e->query_sql_payload_len;
	unsigned int full_params = (e->fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED)
					   ? clamp_capture(e->params_value_len, AUDIT_PARAMS_CAPTURE_MAX)
					   : e->params_value_payload_len;
	unsigned int payoff = event_payload_offset();
	size_t total = (size_t)payoff + names_len + full_sql + full_params;

	char *seg = static_cast<char *>(state->pending.allocate(e->event_seq, total));
	if (!seg) {
		// 空间不足：整条记录从首片起丢弃，后续分片找不到父 seq 也会被丢。
		state->dropped_events++;
		return 0;
	}

	// 段布局：[event 头][names][完整 query_sql][完整 params_value]。
	// main 里两字段首片按最终 layout 落位，params 首片跳到完整 sql 之后。
	state->pending.fill(e->event_seq, 0, e, payoff);
	state->pending.fill(e->event_seq, payoff, e->payload, names_len);
	state->pending.fill(e->event_seq, (size_t)payoff + names_len,
			    event_query_sql(e), e->query_sql_payload_len);
	state->pending.fill(e->event_seq, (size_t)payoff + names_len + full_sql,
			    event_params_value(e), e->params_value_payload_len);
	return 0;
}

static int handle_fragment_record(writer_state *state, const audit_fragment_record *fragment, size_t size)
{
	if (size < audit_fragment_payload_offset())
		return 0;
	if (fragment->total_size != size)
		return 0;
	if (fragment->payload_len > AUDIT_FRAGMENT_PAYLOAD_MAX)
		return 0;
	if (audit_fragment_payload_offset() + fragment->payload_len != fragment->total_size)
		return 0;

	// 找不到父 seq：首片(main)已被丢弃，整条记录从首片起就没进缓冲区，丢弃该分片。
	char *seg = static_cast<char *>(state->pending.find(fragment->parent_event_seq));
	if (!seg)
		return 0;

	event *hdr = reinterpret_cast<event *>(seg);
	unsigned int payoff = event_payload_offset();
	unsigned int names_len = event_names_len(hdr);
	unsigned int full_sql = (hdr->fragment_flags & FRAG_QUERY_SQL_FRAGMENTED)
					? clamp_capture(hdr->query_sql_len, AUDIT_SQL_CAPTURE_MAX)
					: hdr->query_sql_payload_len;

	// 段内绝对 offset = 字段基址 + 分片自带的 fragment_offset(即该字段已填游标)。
	size_t base;
	if (fragment->field == FRAG_FIELD_QUERY_SQL)
		base = (size_t)payoff + names_len;
	else if (fragment->field == FRAG_FIELD_PARAMS_VALUE)
		base = (size_t)payoff + names_len + full_sql;
	else
		return 0;

	// 段已按完整长度预分配，fill 必然落在段内；越界说明数据异常，丢弃整条。
	if (!state->pending.fill(fragment->parent_event_seq, base + fragment->fragment_offset,
				 fragment->payload, fragment->payload_len)) {
		state->pending.erase(fragment->parent_event_seq);
		state->dropped_events++;
		return 0;
	}

	if (fragment->next_fragment_seq != 0 && (fragment->record_flags & AUDIT_RECORD_FLAG_LAST_FRAGMENT) == 0)
		// 非最后一个分片，等待后续分片
		return 0;

	// 尾片到达且记录完整：补齐段头，进发送队列，释放段。
	unsigned int full_params = (hdr->fragment_flags & FRAG_PARAMS_VALUE_FRAGMENTED)
					   ? clamp_capture(hdr->params_value_len, AUDIT_PARAMS_CAPTURE_MAX)
					   : hdr->params_value_payload_len;
	hdr->query_sql_payload_len = full_sql;
	hdr->params_value_payload_len = full_params;
	hdr->record_flags |= AUDIT_RECORD_FLAG_LOGICAL_COMPLETE;
	size_t total = (size_t)payoff + names_len + full_sql + full_params;
	hdr->total_size = (unsigned int)total;
	int ret = append_merged(state, seg, total);
	state->pending.erase(fragment->parent_event_seq);
	return ret;
}

// ringbuf 回调：BPF 程序每提交一条 SQL 审计事件，用户态在这里消费。
static int handle_event(void *ctx, void *data, size_t size)
{
	auto *state = static_cast<writer_state *>(ctx);
	if (size < sizeof(audit_record_header))
		return 0;

	const auto *header = static_cast<const audit_record_header *>(data);
	if (header->total_size != size)
		return 0;
	if (header->record_type == AUDIT_RECORD_EVENT) {
		if (size < event_payload_offset() || size > sizeof(event))
			return 0;
		return handle_main_event(state, static_cast<const event *>(data));
	}
	if (header->record_type == AUDIT_RECORD_FRAGMENT)
		return handle_fragment_record(state, static_cast<const audit_fragment_record *>(data), size);
	return 0;
}

// offset 支持十进制和 0x 前缀十六进制。
static unsigned long long parse_offset(const char *arg)
{
	char *end = nullptr;
	errno = 0;
	unsigned long long offset = strtoull(arg, &end, 0);
	if (errno || *end != '\0') {
		fprintf(stderr, "Invalid offset: %s\n", arg);
		exit(1);
	}
	return offset;
}

int main(int argc, char **argv)
{
	if (argc < 3 || argc > 5) {
		fprintf(stderr, "Usage: %s <target-path> <offset> [config-file]\n", argv[0]);
		fprintf(stderr, "       %s <target-path> <offset> <ignored-output-file> <config-file>\n", argv[0]);
		return 1;
	}

	const char *target = argv[1];
	unsigned long long offset = parse_offset(argv[2]);
	const char *config_file = argc >= 5 ? argv[4] : (argc >= 4 ? argv[3] : "uprobe.conf");
	uprobe_bpf *skel = nullptr;
	bpf_link *link = nullptr;
	ring_buffer *rb = nullptr;
	writer_state state;
	app_config config;
	int err = 0;

	load_config(config_file, &config);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	fill_ipv4_string(state.server_ip, config.server_ip_text.c_str());
	init_grpc_sender(&state.grpc, config);
	print_startup_status(target, offset, config_file, config, state);

	// 打开、加载并通过 verifier 校验 BPF 程序。
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = 1;
		goto cleanup;
	}
	// pid = -1 表示对所有进程生效；target + offset 指定被 hook 的用户态函数入口。
	link = bpf_program__attach_uprobe(skel->progs.handle_uprobe, false, -1, target, offset);
	if (!link) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe to %s+0x%llx\n", target, offset);
		goto cleanup;
	}

	// 绑定 BPF ringbuf map，用户态通过 poll 读取内核提交的事件。
	// 注册handle_event事件回调函数
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &state, nullptr);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("uprobe attach success: %s+0x%llx\n", target, offset);

	while (!exiting) {
		// 等待ringbuf事件，没有事件每100ms返回一次，检查exiting标志
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	state.grpc.stop();
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
