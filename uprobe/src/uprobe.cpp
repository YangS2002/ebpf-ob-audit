// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <csignal>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "audit_upload.grpc.pb.h"

// libbpf 和 skeleton 是 C 接口，C++ 编译时需要保持 C linkage。
extern "C" {
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
}

#include "uprobe.h"

static volatile bool exiting = false;

struct pending_event {
	event main = {};
	std::string query_sql;
	std::string params_value;
	bool has_last_fragment = false;
};

struct app_config {
	std::string agent_id;
	std::string server_ip_text;
	std::string collector_addr;
	unsigned int grpc_batch_bytes = 0;
	unsigned int grpc_timeout_ms = 0;
};

struct grpc_sender {
	bool enabled = false;
	std::string agent_id;
	std::string server_ip;
	unsigned int batch_bytes = 0;
	unsigned int timeout_ms = 0;
	std::vector<char> buffer;
	unsigned long long records = 0;
	unsigned long long sent_batches = 0;
	unsigned long long sent_records = 0;
	unsigned long long sent_bytes = 0;
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<audit::AuditCollector::Stub> stub;
};

struct writer_state {
	FILE *file = nullptr;
	std::vector<char> buffer;
	std::unordered_map<unsigned long long, pending_event> pending;
	unsigned long long consumed_events = 0;
	unsigned long long consumed_bytes = 0;
	unsigned long long written_bytes = 0;
	char server_ip[MAX_IP_LEN] = {};
	grpc_sender grpc;
};

static void handle_signal(int)
{
	exiting = true;
}

static int flush_events(writer_state *state)
{
	if (state->buffer.empty())
		return 0;

	size_t written = fwrite(state->buffer.data(), 1, state->buffer.size(), state->file);
	if (written != state->buffer.size()) {
		fprintf(stderr, "Failed to write event data: %s\n", strerror(errno));
		return -1;
	}
	state->written_bytes += written;
	state->buffer.clear();
	return 0;
}

static int write_file_header(FILE *file)
{
	audit_file_header header = {};
	memcpy(header.magic, AUDIT_FILE_MAGIC, sizeof(AUDIT_FILE_MAGIC));
	header.version = AUDIT_FILE_VERSION;
	header.header_size = sizeof(header);
	header.event_size = sizeof(event);

	if (fwrite(&header, sizeof(header), 1, file) != 1) {
		fprintf(stderr, "Failed to write file header: %s\n", strerror(errno));
		return -1;
	}
	return 0;
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
		else if (key == "grpc_batch_bytes")
			config->grpc_batch_bytes = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
		else if (key == "grpc_timeout_ms")
			config->grpc_timeout_ms = static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
	}
	fclose(file);
	return true;
}

static int grpc_flush(grpc_sender *sender)
{
	if (!sender->enabled || sender->buffer.empty())
		return 0;
	audit::AuditBatch batch;
	batch.set_agent_id(sender->agent_id);
	batch.set_server_ip(sender->server_ip);
	batch.set_file_version(AUDIT_FILE_VERSION);
	batch.set_event_size(sizeof(event));
	batch.set_record_count(sender->records);
	batch.set_records(sender->buffer.data(), sender->buffer.size());

	audit::UploadReply reply;
	grpc::ClientContext context;
	if (sender->timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(sender->timeout_ms));
	grpc::Status status = sender->stub->Upload(&context, batch, &reply);
	if (!status.ok() || !reply.ok()) {
		fprintf(stderr, "grpc upload failed: %s %s\n", status.error_message().c_str(), reply.message().c_str());
		return -1;
	}
	sender->sent_batches++;
	sender->sent_records += sender->records;
	sender->sent_bytes += sender->buffer.size();
	sender->buffer.clear();
	sender->records = 0;
	return 0;
}

static void grpc_append(grpc_sender *sender, const event &e)
{
	if (!sender->enabled)
		return;
	const char *raw = reinterpret_cast<const char *>(&e);
	sender->buffer.insert(sender->buffer.end(), raw, raw + e.total_size);
	sender->records++;
	if (sender->batch_bytes > 0 && sender->buffer.size() >= sender->batch_bytes)
		grpc_flush(sender);
}

static void init_grpc_sender(grpc_sender *sender, const app_config &config)
{
	if (config.collector_addr.empty())
		return;
	sender->enabled = true;
	sender->agent_id = config.agent_id.empty() ? "default-agent" : config.agent_id;
	sender->server_ip = config.server_ip_text;
	sender->batch_bytes = config.grpc_batch_bytes ? config.grpc_batch_bytes : 262144;
	sender->timeout_ms = config.grpc_timeout_ms ? config.grpc_timeout_ms : 2000;
	sender->channel = grpc::CreateChannel(config.collector_addr, grpc::InsecureChannelCredentials());
	sender->stub = audit::AuditCollector::NewStub(sender->channel);
}

static void print_startup_status(const char *target, unsigned long long offset, const char *output_file,
					 const char *config_file, const app_config &config, const writer_state &state)
{
	printf("uprobe config=%s target=%s offset=0x%llx output=%s\n", config_file, target, offset, output_file);
	printf("agent_id=%s server_ip=%s grpc_batch_bytes=%u grpc_timeout_ms=%u\n",
	       config.agent_id.empty() ? "default-agent" : config.agent_id.c_str(),
	       config.server_ip_text.empty() ? "<empty>" : config.server_ip_text.c_str(),
	       config.grpc_batch_bytes ? config.grpc_batch_bytes : 262144,
	       config.grpc_timeout_ms ? config.grpc_timeout_ms : 2000);
	if (!state.grpc.enabled) {
		printf("grpc upload disabled: collector_addr is empty\n");
		return;
	}

	printf("grpc collector target=%s connecting...\n", config.collector_addr.c_str());
	bool ready = state.grpc.channel->WaitForConnected(
		std::chrono::system_clock::now() + std::chrono::milliseconds(config.grpc_timeout_ms ? config.grpc_timeout_ms : 2000));
	printf("grpc collector target=%s state=%s\n", config.collector_addr.c_str(), ready ? "READY" : "NOT_READY");
	if (!ready)
		fprintf(stderr, "grpc collector not ready now; events will still be captured locally, upload attempts use timeout.\n");
}

static int append_event(writer_state *state, const event &e)
{
	if (!event_compact_size_valid(&e))
		return 0;
	event out = e;
	std::memcpy(out.server_ip, state->server_ip, sizeof(out.server_ip));
	const char *raw = reinterpret_cast<const char *>(&out);
	state->buffer.insert(state->buffer.end(), raw, raw + out.total_size);
	grpc_append(&state->grpc, out);
	state->consumed_events++;
	state->consumed_bytes += out.total_size;
	if (state->buffer.size() >= AUDIT_FLUSH_THRESHOLD && flush_events(state) < 0)
		return -1;
	return 0;
}

static bool build_merged_event(pending_event *pending, event *out)
{
	*out = pending->main;
	unsigned int names_len = out->user_name_len + out->proxy_user_name_len + out->tenant_name_len + out->db_name_len;
	if (names_len + pending->query_sql.size() + pending->params_value.size() > AUDIT_EVENT_PAYLOAD_SIZE)
		return false;
	std::memcpy(out->payload + names_len, pending->query_sql.data(), pending->query_sql.size());
	std::memcpy(out->payload + names_len + pending->query_sql.size(), pending->params_value.data(), pending->params_value.size());
	out->query_sql_payload_len = pending->query_sql.size();
	out->params_value_payload_len = pending->params_value.size();
	out->record_flags |= AUDIT_RECORD_FLAG_LOGICAL_COMPLETE;
	out->total_size = event_payload_offset() + names_len + out->query_sql_payload_len + out->params_value_payload_len;
	return true;
}

static int handle_main_event(writer_state *state, const event *e)
{
	if (!event_compact_size_valid(e))
		return 0;
	if ((e->fragment_flags & (FRAG_QUERY_SQL_FRAGMENTED | FRAG_PARAMS_VALUE_FRAGMENTED)) == 0)
		return append_event(state, *e);

	pending_event pending;
	pending.main = *e;
	pending.query_sql.assign(event_query_sql(e), e->query_sql_payload_len);
	pending.params_value.assign(event_params_value(e), e->params_value_payload_len);
	state->pending[e->event_seq] = std::move(pending);
	state->consumed_events++;
	state->consumed_bytes += e->total_size;
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

	auto it = state->pending.find(fragment->parent_event_seq);
	if (it == state->pending.end())
		return 0;

	std::string *target = nullptr;
	if (fragment->field == FRAG_FIELD_QUERY_SQL)
		target = &it->second.query_sql;
	else if (fragment->field == FRAG_FIELD_PARAMS_VALUE)
		target = &it->second.params_value;
	else
		return 0;
	if (fragment->fragment_offset > target->size())
		target->resize(fragment->fragment_offset);
	if (fragment->fragment_offset + fragment->payload_len > target->size())
		target->resize(fragment->fragment_offset + fragment->payload_len);
	if (fragment->payload_len != 0)
		std::memcpy(&(*target)[fragment->fragment_offset], fragment->payload, fragment->payload_len);
	state->consumed_events++;
	state->consumed_bytes += fragment->total_size;

	if (fragment->next_fragment_seq != 0 && (fragment->record_flags & AUDIT_RECORD_FLAG_LAST_FRAGMENT) == 0)
		return 0;

	event merged = {};
	if (!build_merged_event(&it->second, &merged))
		return 0;
	state->pending.erase(it);
	return append_event(state, merged);
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
		fprintf(stderr, "Usage: %s <target-path> <offset> [output-file] [config-file]\n", argv[0]);
		return 1;
	}

	const char *target = argv[1];
	unsigned long long offset = parse_offset(argv[2]);
	const char *output_file = argc >= 4 ? argv[3] : "audit_events.dat";
	const char *config_file = argc == 5 ? argv[4] : "uprobe.conf";
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
	print_startup_status(target, offset, output_file, config_file, config, state);

	state.file = fopen(output_file, "wb");
	if (!state.file) {
		fprintf(stderr, "Failed to open output file %s: %s\n", output_file, strerror(errno));
		return 1;
	}
	state.buffer.reserve(AUDIT_FLUSH_THRESHOLD + sizeof(event));
	if (write_file_header(state.file) < 0) {
		err = 1;
		goto cleanup;
	}

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

	printf("uprobe attach success: %s+0x%llx output=%s\n", target, offset, output_file);

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
	grpc_flush(&state.grpc);
	flush_events(&state);
	if (state.file)
		fclose(state.file);
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
