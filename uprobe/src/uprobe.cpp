// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cerrno>
#include <csignal>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <string>
#include <unordered_set>

// libbpf 和 skeleton 是 C 接口，C++ 编译时需要保持 C linkage。
extern "C" {
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
}

#include "uprobe.h"
#include "agent_logger.h"
#include "audit_accounting.h"
#include "audit_grpc_sender.h"
#include "audit_loss_metrics.h"
#include "ring_buffer/ring_buffer.h"
#include "simple_yaml.h"

// agent 侧默认配置值集中在这里，配置文件缺省时使用这些安全默认值。
static constexpr size_t DEFAULT_PENDING_RINGBUF_BYTES = 16ULL * 1024 * 1024;
static constexpr unsigned int DEFAULT_GRPC_BATCH_BYTES = 262144;
static constexpr unsigned int DEFAULT_GRPC_FLUSH_INTERVAL_MS = 1000;
static constexpr unsigned int DEFAULT_GRPC_TIMEOUT_MS = 2000;
static constexpr unsigned long long DEFAULT_GRPC_POOL_BYTES = 64ULL * 1024 * 1024;
static constexpr unsigned int DEFAULT_GRPC_UPLOAD_CONCURRENCY = 2;
static constexpr unsigned int DEFAULT_GRPC_MAX_RETRIES = 3;
static constexpr unsigned int DEFAULT_GRPC_RETRY_INITIAL_MS = 100;
static constexpr unsigned int DEFAULT_GRPC_RETRY_MAX_MS = 500;
static constexpr unsigned long long DEFAULT_EVENT_SEQ_RESERVE_STEP = 1000000ULL;

static volatile bool exiting = false;

static unsigned long long wall_time_ms()
{
	return (unsigned long long)time(nullptr) * 1000ULL;
}

#if AUDIT_PERF_FIELDS_ENABLED
static unsigned long long monotonic_ns()
{
	struct timespec ts = {};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}
#endif

struct app_config {
	std::string agent_id;
	std::string server_ip_text;
	std::string collector_addr;
	std::string collector_discovery_etcd_endpoints;
	std::string collector_discovery_service_name;
	std::string collector_discovery_selection_policy;
	bool collector_discovery = false;
	bool collector_discovery_watch_enabled = true;
	uint32_t collector_discovery_refresh_interval_ms = 30000;
	uint32_t collector_discovery_rebuild_debounce_ms = 300;
	size_t pending_ringbuf_bytes = DEFAULT_PENDING_RINGBUF_BYTES;
	unsigned int grpc_batch_bytes = DEFAULT_GRPC_BATCH_BYTES;
	unsigned int grpc_flush_interval_ms = DEFAULT_GRPC_FLUSH_INTERVAL_MS;
	unsigned int grpc_timeout_ms = DEFAULT_GRPC_TIMEOUT_MS;
	unsigned long long grpc_pool_bytes = DEFAULT_GRPC_POOL_BYTES;
	unsigned int grpc_upload_concurrency = DEFAULT_GRPC_UPLOAD_CONCURRENCY;
	unsigned int grpc_max_retries = DEFAULT_GRPC_MAX_RETRIES;
	unsigned int grpc_retry_initial_ms = DEFAULT_GRPC_RETRY_INITIAL_MS;
	unsigned int grpc_retry_max_ms = DEFAULT_GRPC_RETRY_MAX_MS;
	unsigned int grpc_keepalive_time_ms = 15000;
	unsigned int grpc_keepalive_timeout_ms = 5000;
	bool grpc_keepalive_permit_without_calls = true;
	std::string event_seq_checkpoint_path;
	unsigned long long event_seq_reserve_step = DEFAULT_EVENT_SEQ_RESERVE_STEP;
};

struct writer_state {
	explicit writer_state(size_t pending_ringbuf_bytes) : pending(pending_ringbuf_bytes) {}

		VarlenRingBuffer<unsigned long long> pending;
		unsigned long long agent_received_records = 0;
		unsigned long long pending_lost_records = 0;
		unsigned long long send_buffer_dropped_records = 0;
		unsigned long long last_event_seq = 0;
		std::unordered_set<unsigned long long> lost_pending_events;
		char server_ip[MAX_IP_LEN] = {};
		std::string agent_id;
		std::string server_ip_text;
		AuditGrpcSender grpc;
		unsigned long long process_start_unix_ms = wall_time_ms();
		unsigned long long metrics_sequence = 0;
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

static bool load_config(const char *path, app_config *config)
{
	if (!path || !*path || !config)
		return false;

	SimpleYaml yaml;
	if (!yaml.load(path))
		return false;

	// 运行时只读取部署脚本生成的 agent.yaml。部署层负责 global/node/override 合并。
	config->agent_id = yaml.get_string("agent.id", config->agent_id);
	config->server_ip_text = yaml.get_string("agent.server_ip", config->server_ip_text);
	config->collector_addr = yaml.get_string("collector.addr", config->collector_addr);
	config->collector_discovery = yaml.get_bool("collector.discovery.enabled", config->collector_discovery);
	config->collector_discovery_etcd_endpoints = yaml.get_string("collector.discovery.etcd_endpoints", config->collector_discovery_etcd_endpoints);
	config->collector_discovery_service_name = yaml.get_string("collector.discovery.service_name", config->collector_discovery_service_name);
	// selection_policy is deprecated on the discovery path (gRPC round_robin is used);
	// still parsed for backward compatibility but ignored for collector selection.
	config->collector_discovery_selection_policy = yaml.get_string("collector.discovery.selection_policy", config->collector_discovery_selection_policy);
	config->collector_discovery_watch_enabled = yaml.get_bool("collector.discovery.watch_enabled", config->collector_discovery_watch_enabled);
	config->collector_discovery_refresh_interval_ms = yaml.get_u32("collector.discovery.refresh_interval_ms", config->collector_discovery_refresh_interval_ms);
	config->collector_discovery_rebuild_debounce_ms = yaml.get_u32("collector.discovery.rebuild_debounce_ms", config->collector_discovery_rebuild_debounce_ms);
	config->pending_ringbuf_bytes = static_cast<size_t>(yaml.get_u64("buffer.pending_ringbuf_bytes", config->pending_ringbuf_bytes));
	config->grpc_batch_bytes = yaml.get_u32("grpc.batch_bytes", config->grpc_batch_bytes);
	config->grpc_flush_interval_ms = yaml.get_u32("grpc.flush_interval_ms", config->grpc_flush_interval_ms);
	config->grpc_timeout_ms = yaml.get_u32("grpc.timeout_ms", config->grpc_timeout_ms);
	config->grpc_pool_bytes = yaml.get_u64("grpc.pool_bytes", config->grpc_pool_bytes);
	config->grpc_upload_concurrency = yaml.get_u32("grpc.upload_concurrency", config->grpc_upload_concurrency);
	config->grpc_max_retries = yaml.get_u32("grpc.max_retries", config->grpc_max_retries);
	config->grpc_retry_initial_ms = yaml.get_u32("grpc.retry_initial_ms", config->grpc_retry_initial_ms);
	config->grpc_retry_max_ms = yaml.get_u32("grpc.retry_max_ms", config->grpc_retry_max_ms);
	config->grpc_keepalive_time_ms = yaml.get_u32("grpc.keepalive_time_ms", config->grpc_keepalive_time_ms);
	config->grpc_keepalive_timeout_ms = yaml.get_u32("grpc.keepalive_timeout_ms", config->grpc_keepalive_timeout_ms);
	config->grpc_keepalive_permit_without_calls = yaml.get_bool("grpc.keepalive_permit_without_calls", config->grpc_keepalive_permit_without_calls);
	config->event_seq_checkpoint_path = yaml.get_string("buffer.event_seq_checkpoint_path", config->event_seq_checkpoint_path);
	config->event_seq_reserve_step = yaml.get_u64("buffer.event_seq_reserve_step", config->event_seq_reserve_step);
	return true;
}

// event_seq 本地持久化：checkpoint 文件只存一个 u64（已预留的序号上界）。
// 启动时读回上界 X 作为 BPF seq 起点，并立即把 X+STEP 写回，等于预留一整块序号；
// 运行中序号逼近上界时再预留下一块。任何已发出的序号都严格小于已落盘的上界，
// 因此进程崩溃后下次启动直接跳到上界不会重号（崩溃时跳号，但序号只用作唯一索引，跳号无碍）。
static unsigned long long read_seq_checkpoint(const std::string &path)
{
	if (path.empty())
		return 0;
	FILE *fp = fopen(path.c_str(), "r");
	if (!fp)
		return 0;
	unsigned long long value = 0;
	if (fscanf(fp, "%llu", &value) != 1)
		value = 0;
	fclose(fp);
	return value;
}

static bool write_seq_checkpoint(const std::string &path, unsigned long long value)
{
	if (path.empty())
		return false;
	std::string tmp = path + ".tmp";
	FILE *fp = fopen(tmp.c_str(), "w");
	if (!fp)
		return false;
	bool ok = fprintf(fp, "%llu\n", value) > 0;
	if (fflush(fp) != 0)
		ok = false;
	fclose(fp);
	if (!ok) {
		remove(tmp.c_str());
		return false;
	}
	return rename(tmp.c_str(), path.c_str()) == 0;
}

static bool bpf_seq_get(uprobe_bpf *skel, unsigned long long *out)
{
	unsigned int key = 0;
	unsigned long long value = 0;
	if (bpf_map__lookup_elem(skel->maps.seq, &key, sizeof(key), &value, sizeof(value), 0) != 0)
		return false;
	*out = value;
	return true;
}

static bool bpf_seq_set(uprobe_bpf *skel, unsigned long long value)
{
	unsigned int key = 0;
	return bpf_map__update_elem(skel->maps.seq, &key, sizeof(key), &value, sizeof(value), 0) == 0;
}

static bool init_grpc_sender(AuditGrpcSender *sender, const app_config &config)
{
	audit_grpc_config grpc_config;
	grpc_config.agent_id = config.agent_id.empty() ? "default-agent" : config.agent_id;
	grpc_config.server_ip = config.server_ip_text;
	grpc_config.collector_addr = config.collector_addr;
	grpc_config.file_version = AUDIT_FILE_VERSION;
	grpc_config.event_size = sizeof(event);
	grpc_config.batch_bytes = config.grpc_batch_bytes;
	grpc_config.flush_interval_ms = config.grpc_flush_interval_ms;
	grpc_config.timeout_ms = config.grpc_timeout_ms;
	grpc_config.pool_bytes = config.grpc_pool_bytes;
	grpc_config.upload_concurrency = config.grpc_upload_concurrency;
	grpc_config.max_retries = config.grpc_max_retries;
	grpc_config.retry_initial_ms = config.grpc_retry_initial_ms;
	grpc_config.retry_max_ms = config.grpc_retry_max_ms;
	grpc_config.keepalive_time_ms = config.grpc_keepalive_time_ms;
	grpc_config.keepalive_timeout_ms = config.grpc_keepalive_timeout_ms;
	grpc_config.keepalive_permit_without_calls = config.grpc_keepalive_permit_without_calls;
	if (config.collector_discovery && !config.collector_discovery_etcd_endpoints.empty()) {
		std::unique_ptr<CollectorResolver> resolver(new EtcdCollectorResolver(
			config.collector_discovery_etcd_endpoints,
			config.collector_discovery_service_name.empty() ? "audit-collector" : config.collector_discovery_service_name,
			grpc_config.agent_id,
			config.collector_discovery_selection_policy.empty() ? "first" : config.collector_discovery_selection_policy,
			config.collector_discovery_watch_enabled,
			config.collector_discovery_refresh_interval_ms,
			config.collector_discovery_rebuild_debounce_ms));
		return sender->start(grpc_config, std::move(resolver));
	}
	return sender->start(grpc_config);
}

static void print_startup_status(const char *target, unsigned long long offset,
						 const char *config_file, const app_config &config, const writer_state &state)
{
	agent_log_info("event=startup config=%s target=%s offset=0x%llx", config_file, target, offset);
	agent_log_info("event=agent_config agent_id=%s server_ip=%s pending_ringbuf_bytes=%zu grpc_batch_bytes=%u grpc_flush_interval_ms=%u grpc_timeout_ms=%u grpc_pool_bytes=%llu grpc_upload_concurrency=%u grpc_max_retries=%u grpc_retry_initial_ms=%u grpc_retry_max_ms=%u discovery=%s",
	       config.agent_id.empty() ? "default-agent" : config.agent_id.c_str(),
	       config.server_ip_text.empty() ? "<empty>" : config.server_ip_text.c_str(),
	       state.pending.capacity(),
	       config.grpc_batch_bytes,
	       config.grpc_flush_interval_ms,
	       config.grpc_timeout_ms,
	       config.grpc_pool_bytes,
	       config.grpc_upload_concurrency,
	       config.grpc_max_retries,
	       config.grpc_retry_initial_ms,
	       config.grpc_retry_max_ms,
	       config.collector_discovery ? "true" : "false");
	if (!state.grpc.enabled()) {
		agent_log_error("event=collector_disabled reason=no_collector_available");
		return;
	}

	std::string current_collector = state.grpc.current_collector();
	const char *target_addr = current_collector.empty()
		? (config.collector_discovery ? "<none>" : config.collector_addr.c_str())
		: current_collector.c_str();
	agent_log_info("event=collector_connect discovery=%s target=%s",
	       config.collector_discovery ? "etcd" : "static", target_addr);
	bool ready = state.grpc.wait_ready(config.grpc_timeout_ms);
	agent_log_info("event=collector_state state=%s", ready ? "READY" : "NOT_READY");
	if (!ready)
		agent_log_error("event=collector_not_ready action=capture_local");
}

#if AUDIT_GRPC_TIMING_ENABLED
static void print_grpc_timing_stats(const writer_state &state)
{
	audit_grpc_stats stats = state.grpc.stats();
	double avg_rtt_us = stats.sent_batches
		? (double)stats.total_grpc_roundtrip_ns / stats.sent_batches / 1000.0 : 0;
	double avg_submit_us = stats.submit_calls
		? (double)stats.total_submit_ns / stats.submit_calls / 1000.0 : 0;

	agent_log_info("event=agent_metrics sent_batches=%llu sent_records=%llu sent_bytes=%llu failed_uploads=%llu retry_uploads=%llu dropped_records=%llu dropped_after_retries_batches=%llu avg_rtt_us=%.3f median_rtt_us=%.3f max_rtt_us=%.3f last_rtt_us=%.3f avg_submit_us=%.3f max_submit_us=%.3f max_active_workers=%u max_ready_batches=%u pool_total_batches=%u pool_free_batches=%u",
	       (unsigned long long)stats.sent_batches,
	       (unsigned long long)stats.sent_records,
	       (unsigned long long)stats.sent_bytes,
	       (unsigned long long)stats.failed_uploads,
	       (unsigned long long)stats.retry_uploads,
	       (unsigned long long)stats.dropped_records,
	       (unsigned long long)stats.dropped_after_retries_batches,
	       avg_rtt_us,
	       stats.median_grpc_roundtrip_ns / 1000.0,
	       stats.max_grpc_roundtrip_ns / 1000.0,
	       stats.last_grpc_roundtrip_ns / 1000.0,
	       avg_submit_us,
	       stats.max_submit_ns / 1000.0,
	       stats.max_active_workers,
	       stats.max_ready_batches,
	       stats.pool_total_batches,
	       stats.pool_free_batches);
}
#endif

static audit_agent_accounting_snapshot make_agent_accounting_snapshot(writer_state &state,
							 const audit_bpf_loss_stats &bpf_stats,
							 bool advance_sequence)
{
	audit_grpc_stats grpc_stats = state.grpc.stats();
	audit_agent_accounting_snapshot snapshot;
	snapshot.source_id = state.agent_id.empty() ? "default-agent" : state.agent_id;
	snapshot.server_ip = state.server_ip_text;
	snapshot.process_start_unix_ms = state.process_start_unix_ms;
	snapshot.sequence = advance_sequence ? ++state.metrics_sequence : state.metrics_sequence;
	snapshot.report_unix_ms = wall_time_ms();
	snapshot.ob_audit_seen_records = bpf_stats.ob_audit_seen_records;
	snapshot.ringbuf_lost_records = bpf_stats.ringbuf_full_dropped_records;
	snapshot.agent_received_records = state.agent_received_records;
	snapshot.pending_lost_records = state.pending_lost_records;
	snapshot.send_enqueue_lost_records = state.send_buffer_dropped_records;
	snapshot.collector_rejected_records = grpc_stats.collector_rejected_records;
	snapshot.collector_queue_full_records = grpc_stats.collector_queue_full_records;
	snapshot.upload_retry_exhausted_records = grpc_stats.dropped_after_retries_records;
	snapshot.agent_lost_records = snapshot.ringbuf_lost_records + snapshot.pending_lost_records +
		snapshot.send_enqueue_lost_records + snapshot.upload_retry_exhausted_records;
	snapshot.sender_accepted_records = grpc_stats.accepted_records;
	snapshot.delivered_records = grpc_stats.sent_records;
	snapshot.acknowledged_records = grpc_stats.acknowledged_records;
	snapshot.pending_inflight_records = state.pending.size();
	snapshot.sender_inflight_records = grpc_stats.accepted_records - grpc_stats.acknowledged_records -
		grpc_stats.dropped_after_retries_records;
	snapshot.inflight_records = snapshot.pending_inflight_records + snapshot.sender_inflight_records;
	return snapshot;
}

static void print_agent_loss_metrics(writer_state &state, const audit_bpf_loss_stats &bpf_stats)
{
	audit_agent_accounting_snapshot snapshot = make_agent_accounting_snapshot(state, bpf_stats, false);
	agent_log_info("event=agent_audit_accounting ob_audit_seen_records=%llu ringbuf_lost_records=%llu agent_received_records=%llu pending_lost_records=%llu send_enqueue_lost_records=%llu collector_rejected_records=%llu collector_queue_full_records=%llu upload_retry_exhausted_records=%llu agent_lost_records=%llu delivered_records=%llu acknowledged_records=%llu inflight_records=%llu event_seq_last=%llu",
       (unsigned long long)snapshot.ob_audit_seen_records,
       (unsigned long long)snapshot.ringbuf_lost_records,
       (unsigned long long)snapshot.agent_received_records,
       (unsigned long long)snapshot.pending_lost_records,
       (unsigned long long)snapshot.send_enqueue_lost_records,
       (unsigned long long)snapshot.collector_rejected_records,
       (unsigned long long)snapshot.collector_queue_full_records,
       (unsigned long long)snapshot.upload_retry_exhausted_records,
       (unsigned long long)snapshot.agent_lost_records,
       (unsigned long long)snapshot.delivered_records,
       (unsigned long long)snapshot.acknowledged_records,
       (unsigned long long)snapshot.inflight_records,
       state.last_event_seq);
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
static int emit_record(writer_state *state, char *data, size_t size)
{
#if AUDIT_PERF_FIELDS_ENABLED
	event *hdr = reinterpret_cast<event *>(data);
	hdr->perf_agent_before_submit_ns = monotonic_ns();
#endif
	bool submitted = state->grpc.submit(data, size);
	if (!submitted) {
		state->send_buffer_dropped_records++;
		return 0;
	}
	return 0;
}

static void mark_pending_lost(writer_state *state, unsigned long long event_seq)
{
	if (event_seq == 0)
		return;
	if (state->lost_pending_events.insert(event_seq).second)
		state->pending_lost_records++;
}

// 未分片小事件：直接从内核 ringbuf 拷入发送批次，省掉中间栈缓冲整拷。
static int append_event(writer_state *state, const event *e, unsigned long long agent_receive_ns)
{
	if (!event_compact_size_valid(e))
		return 0;
	unsigned int total = e->total_size;
	if (total > AUDIT_RINGBUF_BUCKET_MAIN)
		return 0;
#if AUDIT_PERF_FIELDS_ENABLED
	// perf 模式保留栈缓冲：需按序写入 before/after_submit 时间戳。
	char buf[AUDIT_RINGBUF_BUCKET_MAIN];
	std::memcpy(buf, e, total);
	event *out = reinterpret_cast<event *>(buf);
	out->perf_agent_receive_ns = agent_receive_ns;
	std::memcpy(out->server_ip, state->server_ip, sizeof(out->server_ip));
	return emit_record(state, buf, total);
#else
	(void)agent_receive_ns;
	// 快路径：单次拷贝(ringbuf→批次)，拷入后由 sender 就地回填 server_ip。
	bool submitted = state->grpc.submit(reinterpret_cast<const char *>(e), total,
					    state->server_ip, offsetof(event, server_ip), sizeof(e->server_ip));
	if (!submitted)
		state->send_buffer_dropped_records++;
	return 0;
#endif
}

// 合并完成的变长事件：段可写，直接在段头填 server_ip 再发。
static int append_merged(writer_state *state, char *seg, size_t size)
{
	event *hdr = reinterpret_cast<event *>(seg);
	std::memcpy(hdr->server_ip, state->server_ip, sizeof(hdr->server_ip));
	return emit_record(state, seg, size);
}

static int handle_main_event(writer_state *state, const event *e, unsigned long long agent_receive_ns)
{
	if (!event_compact_size_valid(e))
		return 0;
	if ((e->fragment_flags & (FRAG_QUERY_SQL_FRAGMENTED | FRAG_PARAMS_VALUE_FRAGMENTED)) == 0)
		return append_event(state, e, agent_receive_ns);

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
			mark_pending_lost(state, e->event_seq);
			return 0;
		}

	// 段布局：[event 头][names][完整 query_sql][完整 params_value]。
	// main 里两字段首片按最终 layout 落位，params 首片跳到完整 sql 之后。
	state->pending.fill(e->event_seq, 0, e, payoff);
#if AUDIT_PERF_FIELDS_ENABLED
	reinterpret_cast<event *>(seg)->perf_agent_receive_ns = agent_receive_ns;
#endif
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
	if (!seg) {
		mark_pending_lost(state, fragment->parent_event_seq);
		return 0;
	}

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
		mark_pending_lost(state, fragment->parent_event_seq);
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
	state->lost_pending_events.erase(fragment->parent_event_seq);
	state->pending.erase(fragment->parent_event_seq);
	return ret;
}

// ringbuf 回调：BPF 程序每提交一条 SQL 审计事件，用户态在这里消费。
static int handle_event(void *ctx, void *data, size_t size)
{
	auto *state = static_cast<writer_state *>(ctx);
#if AUDIT_PERF_FIELDS_ENABLED
	unsigned long long agent_receive_ns = monotonic_ns();
#endif
	if (size < sizeof(audit_record_header))
		return 0;

	const auto *header = static_cast<const audit_record_header *>(data);
	if (header->total_size > size)
		return 0;
	if (header->record_type == AUDIT_RECORD_EVENT) {
		if (header->total_size < event_payload_offset() || header->total_size > sizeof(event))
			return 0;
		const event *e = static_cast<const event *>(data);
		state->agent_received_records++;
		state->last_event_seq = e->event_seq;
	#if AUDIT_PERF_FIELDS_ENABLED
		return handle_main_event(state, e, agent_receive_ns);
	#else
		return handle_main_event(state, e, 0);
	#endif
	}
	if (header->record_type == AUDIT_RECORD_FRAGMENT)
		return handle_fragment_record(state, static_cast<const audit_fragment_record *>(data), header->total_size);
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
	const char *config_file = argc >= 5 ? argv[4] : (argc >= 4 ? argv[3] : "agent.yaml");
	const char *log_file = getenv("UPROBE_LOG_FILE");
	if (!log_file || !*log_file)
		log_file = "agent.log";
	agent_log_init(log_file);
	uprobe_bpf *skel = nullptr;
	bpf_link *link = nullptr;
	ring_buffer *rb = nullptr;
	app_config config;
	int err = 0;
	unsigned long long seq_reserved_upper = 0;
	std::thread *metrics_thread = nullptr;
	load_config(config_file, &config);

	std::unique_ptr<writer_state> state(new (std::nothrow) writer_state(config.pending_ringbuf_bytes));
	if (!state || !state->pending.valid()) {
		agent_log_error("event=pending_ringbuf_alloc_failed bytes=%zu", config.pending_ringbuf_bytes);
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	fill_ipv4_string(state->server_ip, config.server_ip_text.c_str());
	state->agent_id = config.agent_id.empty() ? "default-agent" : config.agent_id;
	state->server_ip_text = config.server_ip_text;
	if (!init_grpc_sender(&state->grpc, config)) {
		agent_log_error("event=grpc_sender_start_failed");
		err = 1;
		goto cleanup;
	}
	print_startup_status(target, offset, config_file, config, *state);

	// 打开、加载并通过 verifier 校验 BPF 程序。
	agent_log_info("event=bpf_load_begin");
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		agent_log_error("event=bpf_load_failed errno=%d", errno);
		err = 1;
		goto cleanup;
	}
	agent_log_info("event=bpf_load_success");
	// event_seq 起点恢复：读回已持久化上界，跳过一整块预留区间，保证跨重启序号不重复。
	if (!config.event_seq_checkpoint_path.empty()) {
		unsigned long long step = config.event_seq_reserve_step ? config.event_seq_reserve_step : DEFAULT_EVENT_SEQ_RESERVE_STEP;
		unsigned long long seq_start = read_seq_checkpoint(config.event_seq_checkpoint_path);
		seq_reserved_upper = seq_start + step;
		if (!write_seq_checkpoint(config.event_seq_checkpoint_path, seq_reserved_upper))
			agent_log_error("event=event_seq_checkpoint_write_failed path=%s", config.event_seq_checkpoint_path.c_str());
		if (!bpf_seq_set(skel, seq_start))
			agent_log_error("event=event_seq_map_init_failed start=%llu", seq_start);
		else
			agent_log_info("event=event_seq_restored start=%llu reserved_upper=%llu step=%llu", seq_start, seq_reserved_upper, step);
	}
	// pid = -1 表示对所有进程生效；target + offset 指定被 hook 的用户态函数入口。
	agent_log_info("event=attach_begin target=%s offset=0x%llx", target, offset);
	link = bpf_program__attach_uprobe(skel->progs.handle_uprobe, false, -1, target, offset);
	if (!link) {
		err = -errno;
		agent_log_error("event=attach_failed target=%s offset=0x%llx", target, offset);
		goto cleanup;
	}

	// 绑定 BPF ringbuf map，用户态通过 poll 读取内核提交的事件。
	// 注册handle_event事件回调函数
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, state.get(), nullptr);
	if (!rb) {
		err = -1;
		agent_log_error("event=ring_buffer_create_failed");
		goto cleanup;
	}

	agent_log_info("event=attach_success target=%s offset=0x%llx", target, offset);

		// 指标上报 + seq checkpoint 放到独立线程：report_metrics 是阻塞 grpc 调用，
		// collector 慢/不可达时会卡住调用线程。若与 ring poll 同线程，会停住 ringbuf
		// 消费导致内核 ringbuf 打满丢包(4/5 节点实测 ringbuf_lost 与上报失败同时出现)。
		// 独立线程后，上报无论成败都不阻塞 ring 消费。
		metrics_thread = new (std::nothrow) std::thread([&]() {
			unsigned long long last_report_ms = 0;
			while (!exiting) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				unsigned long long now_ms = wall_time_ms();
				if (last_report_ms != 0 && now_ms - last_report_ms < 10000)
					continue;
				last_report_ms = now_ms;
				audit_bpf_loss_stats bpf_stats = {};
				unsigned int key = 0;
				bpf_map__lookup_elem(skel->maps.loss_stats, &key, sizeof(key), &bpf_stats, sizeof(bpf_stats), 0);
				audit_agent_accounting_snapshot snapshot = make_agent_accounting_snapshot(*state, bpf_stats, true);
				if (!state->grpc.report_metrics(snapshot))
					agent_log_error("event=agent_metrics_report_failed sequence=%llu", (unsigned long long)snapshot.sequence);
				// 序号逼近预留上界时再预留一块并落盘（约每 STEP 条写一次，开销极低）。
				if (!config.event_seq_checkpoint_path.empty()) {
					unsigned long long step = config.event_seq_reserve_step ? config.event_seq_reserve_step : DEFAULT_EVENT_SEQ_RESERVE_STEP;
					unsigned long long cur = 0;
					if (bpf_seq_get(skel, &cur) && cur + step / 2 >= seq_reserved_upper) {
						seq_reserved_upper = cur + step;
						if (!write_seq_checkpoint(config.event_seq_checkpoint_path, seq_reserved_upper))
							agent_log_error("event=event_seq_checkpoint_write_failed path=%s", config.event_seq_checkpoint_path.c_str());
					}
				}
			}
		});
		if (!metrics_thread)
			agent_log_error("event=metrics_thread_create_failed");

		// BPF 侧 submit 使用 BPF_RB_NO_WAKEUP：不依赖 epoll 唤醒，改为自轮询。
		// 空闲退避：连续空轮询时睡眠从 idle_min 线性增长到 idle_max，降低空闲空转 CPU；
		// 一旦抽到数据立即清零(0 睡，低延迟)。高负载下 consume 持续 >0，永不睡，无延迟影响。
		{
			// 实测(agent perf)：睡眠/唤醒的上下文切换占 agent CPU ~29%，是最大头。
			// 稳态负载下「抽干→睡」循环频率 ≈ 1/idle_min，idle_min=1ms 即 ~1000 次/s。
			// idle_max=5ms 对齐 gRPC flush_interval(5ms)：ringbuf 层延迟本来就被
			// 批次 flush 兜底，更短的轮询上限没有收益，只增加 schedule churn。
			const unsigned int idle_min_us = 1000;
			const unsigned int idle_max_us = 5000;
			const unsigned int idle_step_us = 500;
			unsigned int idle_sleep_us = 0;
			while (!exiting) {
				int consumed = ring_buffer__consume(rb);
				if (consumed == -EINTR) {
					err = 0;
					break;
				}
				if (consumed < 0) {
					err = consumed;
					agent_log_error("event=ring_buffer_consume_failed err=%d", err);
					break;
				}
				if (consumed > 0) {
					idle_sleep_us = 0;
					continue;
				}
				idle_sleep_us = idle_sleep_us < idle_min_us
							? idle_min_us
							: (idle_sleep_us + idle_step_us > idle_max_us ? idle_max_us : idle_sleep_us + idle_step_us);
				std::this_thread::sleep_for(std::chrono::microseconds(idle_sleep_us));
			}
		}

	cleanup:
		// 先停指标线程并 join，保证后续最终上报不与其并发调用 report_metrics。
		exiting = true;
		if (metrics_thread) {
			metrics_thread->join();
			delete metrics_thread;
			metrics_thread = nullptr;
		}
		if (state) {
			// 退出补发：先把内核 ringbuf 里残留事件抽干进发送队列，避免退出丢内存数据。
			if (rb)
				ring_buffer__consume(rb);
			// consume 后仍留在 pending 的都是缺少尾部分片的未完成记录，不能发送不完整数据。
			// 退出时统一转入 pending_lost，使最终对账闭合。
			state->pending_lost_records += state->pending.clear();
			// 封口并等待 sender 队列、上传 RPC 和重试全部完成，再取最终快照。
			if (state->grpc.enabled() && !state->grpc.flush())
				agent_log_error("event=agent_sender_flush_failed");
			audit_bpf_loss_stats bpf_stats = {};
			if (skel) {
				unsigned int key = 0;
				bpf_map__lookup_elem(skel->maps.loss_stats, &key, sizeof(key), &bpf_stats, sizeof(bpf_stats), 0);
			}
			// 退出前补发一次最终指标，减少"上次上报到退出"之间的对账缺口。
			if (state->grpc.enabled()) {
				audit_agent_accounting_snapshot final_snapshot = make_agent_accounting_snapshot(*state, bpf_stats, true);
				if (!state->grpc.report_metrics(final_snapshot))
					agent_log_error("event=agent_final_metrics_report_failed sequence=%llu", (unsigned long long)final_snapshot.sequence);
			}
			print_agent_loss_metrics(*state, bpf_stats);
	#if AUDIT_GRPC_TIMING_ENABLED
			print_grpc_timing_stats(*state);
	#endif
			// 落盘当前实际序号，下次启动只需再跳一块，避免每次重启浪费整块预留。
			if (skel && !config.event_seq_checkpoint_path.empty()) {
				unsigned long long cur = 0;
				if (bpf_seq_get(skel, &cur))
					write_seq_checkpoint(config.event_seq_checkpoint_path, cur);
			}
			state->grpc.stop();
		}
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);
	agent_log_close();
	return err < 0 ? -err : err;
}
