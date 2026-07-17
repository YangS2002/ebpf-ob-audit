// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

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

struct writer_state {
	FILE *file = nullptr;
	std::vector<char> buffer;
	std::unordered_map<unsigned long long, pending_event> pending;
	unsigned long long consumed_events = 0;
	unsigned long long consumed_bytes = 0;
	unsigned long long written_bytes = 0;
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
   
static int append_event(writer_state *state, const event &e)
{
	if (!event_compact_size_valid(&e))
		return 0;
	const char *raw = reinterpret_cast<const char *>(&e);
	state->buffer.insert(state->buffer.end(), raw, raw + e.total_size);
	state->consumed_events++;
	state->consumed_bytes += e.total_size;
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
	if (argc < 3 || argc > 4) {
		fprintf(stderr, "Usage: %s <target-path> <offset> [output-file]\n", argv[0]);
		return 1;
	}

	const char *target = argv[1];
	unsigned long long offset = parse_offset(argv[2]);
	const char *output_file = argc == 4 ? argv[3] : "audit_events.dat";
	uprobe_bpf *skel = nullptr;
	bpf_link *link = nullptr;
	ring_buffer *rb = nullptr;
	writer_state state;
	int err = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

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
	flush_events(&state);
	if (state.file)
		fclose(state.file);
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
