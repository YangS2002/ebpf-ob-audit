// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "mongodb_sink.h"
#include "audit_schema.h"
#include "../tools/audit_format.h"

#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#if __has_include(<mongoc/mongoc.h>)
#define HAVE_MONGOC 1
#include <mongoc/mongoc.h>
#else
#define HAVE_MONGOC 0
#endif

#if AUDIT_PERF_FIELDS_ENABLED || AUDIT_GRPC_TIMING_ENABLED
static unsigned long long monotonic_ns()
{
	return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}
#endif

#if AUDIT_GRPC_TIMING_ENABLED
#define AUDIT_TIMING_NOW() monotonic_ns()
#else
#define AUDIT_TIMING_NOW() 0ULL
#endif

#if HAVE_MONGOC
// Context handed to each field appender. Bundles everything a writer might need
// so appenders can be captureless (convertible to plain function pointers).
struct append_ctx {
	const event *e;
	const char *agent_id;
	const char *indexed_server_ip;
	const audit_ingest::parsed_audit_event *parsed;
	int64_t ingest_time_ms;
	unsigned long long mongo_before_insert_ns;
};

using append_fn = void (*)(bson_t *, const char *, const append_ctx &);

// One resolved (numeric-key -> writer) pair, built from the loaded schema.
struct emit_entry {
	std::string key;
	append_fn fn;
};
#endif

struct MongoSink::Impl {
	mongodb_config config;
#if HAVE_MONGOC
	mongoc_client_pool_t *pool = nullptr;
	mongoc_write_concern_t *write_concern = nullptr;
	std::vector<emit_entry> emit_plan;
#endif
	int schema_version = 0;
	bool started = false;
};

// Field encoding is driven entirely by the external schema file (see
// audit_schema.h). At startup the loaded schema is resolved against the
// appender registry below into an ordered emit plan; every event document is
// written under numeric string keys plus an `sv` schema-version marker. The
// schema itself is stored once per version in the separate `audit_schemas`
// collection (see ensure_schema_dict) so readers can decode by version.


#if HAVE_MONGOC
// Resolve a required full field name to its numeric key from the loaded schema.
static bool schema_key_for(const std::unordered_map<std::string, std::string> &full_to_key,
			   const char *full_name, std::string *key, std::string *error)
{
	auto it = full_to_key.find(full_name);
	if (it == full_to_key.end()) {
		if (error)
			*error = std::string("schema is missing required index field '") + full_name + "'";
		return false;
	}
	*key = it->second;
	return true;
}

static bool ensure_unique_index(mongoc_client_t *client, const mongodb_config &config,
				const std::unordered_map<std::string, std::string> &full_to_key,
				std::string *error)
{
	std::string tenant_key, server_key, event_key;
	if (!schema_key_for(full_to_key, "tenant_id", &tenant_key, error) ||
	    !schema_key_for(full_to_key, "server_ip", &server_key, error) ||
	    !schema_key_for(full_to_key, "event_seq", &event_key, error))
		return false;

	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, config.database.c_str(), config.collection.c_str());
	if (!collection) {
		if (error)
			*error = "failed to get MongoDB collection";
		return false;
	}

	bson_t keys;
	bson_init(&keys);
	BSON_APPEND_INT32(&keys, tenant_key.c_str(), 1);
	BSON_APPEND_INT32(&keys, server_key.c_str(), 1);
	BSON_APPEND_INT32(&keys, event_key.c_str(), 1);

	bson_error_t bson_error;
	mongoc_index_opt_t opts;
	mongoc_index_opt_init(&opts);
	opts.name = "uniq_tenant_server_event_seq";
	opts.unique = true;

	bool ok = mongoc_collection_create_index(collection, &keys, &opts, &bson_error);
	bson_destroy(&keys);
	mongoc_collection_destroy(collection);

	if (!ok && strstr(bson_error.message, "already exists") == nullptr) {
		if (error)
			*error = bson_error.message;
		return false;
	}
	return true;
}

static bool ensure_ttl_index(mongoc_client_t *client, const std::string &database, const std::string &collection_name,
				     const char *field, unsigned int ttl_days, std::string *error)
{
	if (ttl_days == 0)
		return true;
	mongoc_collection_t *collection = mongoc_client_get_collection(client, database.c_str(), collection_name.c_str());
	if (!collection) {
		if (error)
			*error = "failed to get MongoDB collection for TTL index";
		return false;
	}

	bson_t keys;
	bson_init(&keys);
	BSON_APPEND_INT32(&keys, field, 1);

	bson_error_t bson_error;
	mongoc_index_opt_t opts;
	mongoc_index_opt_init(&opts);
	std::string name = std::string("ttl_") + field;
	opts.name = name.c_str();
	opts.expire_after_seconds = (int32_t)ttl_days * 86400;

	bool ok = mongoc_collection_create_index(collection, &keys, &opts, &bson_error);
	bson_destroy(&keys);
	mongoc_collection_destroy(collection);

	if (!ok && strstr(bson_error.message, "already exists") == nullptr) {
		if (error)
			*error = bson_error.message;
		return false;
	}
	return true;
}

// Non-unique compound index `{first_key:1, second_key:1}` on the events
// collection. Idempotent: an "already exists" error is treated as success.
static bool create_compound_index(mongoc_client_t *client, const mongodb_config &config,
				  const char *first_key, const char *second_key,
				  const char *name, std::string *error)
{
	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, config.database.c_str(), config.collection.c_str());
	if (!collection) {
		if (error)
			*error = "failed to get MongoDB collection for secondary index";
		return false;
	}

	bson_t keys;
	bson_init(&keys);
	BSON_APPEND_INT32(&keys, first_key, 1);
	BSON_APPEND_INT32(&keys, second_key, 1);

	bson_error_t bson_error;
	mongoc_index_opt_t opts;
	mongoc_index_opt_init(&opts);
	opts.name = name;

	bool ok = mongoc_collection_create_index(collection, &keys, &opts, &bson_error);
	bson_destroy(&keys);
	mongoc_collection_destroy(collection);

	if (!ok && strstr(bson_error.message, "already exists") == nullptr) {
		if (error)
			*error = bson_error.message;
		return false;
	}
	return true;
}

// Secondary indexes for business filter/range queries. Each is a non-unique
// compound index ending in the top-level `ingest_time` (a real named BSON
// DATE_TIME field, see append_event_doc) so time-range queries use the index.
// Fields not present in the active schema are skipped rather than fatal.
static bool ensure_secondary_indexes(mongoc_client_t *client, const mongodb_config &config,
				     const std::unordered_map<std::string, std::string> &full_to_key,
				     std::string *error)
{
	std::string tenant_name_key, server_key;
	if (schema_key_for(full_to_key, "tenant_name", &tenant_name_key, nullptr) &&
	    !create_compound_index(client, config, tenant_name_key.c_str(), "ingest_time", "idx_tenant_time", error))
		return false;
	if (schema_key_for(full_to_key, "server_ip", &server_key, nullptr) &&
	    !create_compound_index(client, config, server_key.c_str(), "ingest_time", "idx_server_time", error))
		return false;
	return true;
}

// Upsert the schema document `{ _id: <version>, version, fields: { key -> full } }`// into the dedicated schema collection. Keyed by version so multiple versions
// coexist; idempotent, so safe to run on every startup.
static bool ensure_schema_dict(mongoc_client_t *client, const mongodb_config &config,
			       const audit_schema &schema, std::string *error)
{
	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, config.database.c_str(), config.schema_collection.c_str());
	if (!collection) {
		if (error)
			*error = "failed to get MongoDB schema collection";
		return false;
	}

	bson_t update;
	bson_t set;
	bson_t fields;
	bson_init(&update);
	bson_append_document_begin(&update, "$set", -1, &set);
	BSON_APPEND_INT32(&set, "version", schema.version);
	bson_append_document_begin(&set, "fields", -1, &fields);
	for (const auto &f : schema.fields)
		BSON_APPEND_UTF8(&fields, f.first.c_str(), f.second.c_str());
	bson_append_document_end(&set, &fields);
	bson_append_document_end(&update, &set);

	bson_t selector;
	bson_init(&selector);
	BSON_APPEND_INT32(&selector, "_id", schema.version);

	bson_t opts;
	bson_init(&opts);
	BSON_APPEND_BOOL(&opts, "upsert", true);

	bson_error_t bson_error;
	bool ok = mongoc_collection_update_one(collection, &selector, &update, &opts, nullptr, &bson_error);

	bson_destroy(&opts);
	bson_destroy(&selector);
	bson_destroy(&update);
	mongoc_collection_destroy(collection);

	if (!ok) {
		if (error)
			*error = bson_error.message;
		return false;
	}
	return true;
}

static std::string format_ob_addr_for_mongo(const char *data, size_t max_len)
{
	if (max_len < OB_ADDR_SIZE)
		return "";
	int version = 0;
	unsigned int ip = 0;
	memcpy(&version, data + OB_ADDR_VERSION_OFF, sizeof(version));
	if (version != 4)
		return "";
	memcpy(&ip, data + OB_ADDR_IP_OFF, sizeof(ip));
	if (ip == 0)
		return "";
	char buf[16] = {};
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip >> 24) & 0xff, (ip >> 16) & 0xff,
		 (ip >> 8) & 0xff, ip & 0xff);
	return std::string(buf);
}

static std::string format_trace_id_for_mongo(const ob_trace_id_raw &trace_id)
{
	char buf[128] = {};
	unsigned long long u0 = trace_id.uval[0];
	unsigned int bytes_no_ip = (unsigned int)(u0 >> 32);
	bool is_ipv6 = ((bytes_no_ip >> 17) & 0x1) != 0;
	if (!is_ipv6) {
		snprintf(buf, sizeof(buf), "Y%llX-%016llX-%llX-%llX",
			 trace_id.uval[0], trace_id.uval[1], trace_id.uval[2], trace_id.uval[3]);
	} else {
		snprintf(buf, sizeof(buf), "Y%X-%016llX-%llX-%llX",
			 bytes_no_ip, trace_id.uval[1], trace_id.uval[2], trace_id.uval[3]);
	}
	return std::string(buf);
}

static const char *trans_status_to_ob_sql_audit_string_for_mongo(int trans_status)
{
	switch (trans_status) {
	case 1:
		return "Transaction not opened";
	case 2:
		return "Enable implicit transactions";
	case 3:
		return "Enable committable transaction";
	default:
		return "Unknown status";
	}
}

static bool append_text(bson_t *doc, const char *key, const char *data, unsigned int len)
{
	return bson_append_utf8(doc, key, -1, data, (int)len);
}

// Registry of every field the collector knows how to write, keyed by full name.
// The external schema decides which of these are emitted and under what numeric
// key. Appenders are captureless lambdas so they collapse to function pointers.
struct field_appender {
	const char *full_name;
	append_fn fn;
};

static const field_appender kFieldAppenders[] = {
	{"total_size", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.e->total_size); }},
	{"record_type", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.e->record_type); }},
	{"record_flags", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.e->record_flags); }},
	{"event_seq", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->event_seq); }},
	{"parent_event_seq", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->parent_event_seq); }},
	{"next_fragment_seq", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->next_fragment_seq); }},
	{"user_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->user_id); }},
	{"tenant_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->tenant_id); }},
	{"effective_tenant_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->effective_tenant_id); }},
	{"session_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->session_id); }},
	{"proxy_session_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->proxy_session_id); }},
	{"db_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->db_id); }},
	{"affected_rows", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->affected_rows); }},
	{"return_rows", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->return_rows); }},
	{"transaction_hash", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->transaction_hash); }},
	{"request_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->request_id); }},
	{"request_timestamp", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, c.e->request_timestamp); }},
	{"elapsed_time", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, c.e->elapsed_time); }},
	{"execute_time", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, c.e->execute_time); }},
	{"query_sql_len", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, c.e->query_sql_len); }},
	{"params_value_len", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, c.e->params_value_len); }},
#if AUDIT_PERF_FIELDS_ENABLED
	{"perf_bpf_entry_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_bpf_entry_ns); }},
	{"perf_bpf_before_output_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_bpf_before_output_ns); }},
	{"perf_agent_receive_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_agent_receive_ns); }},
	{"perf_agent_before_submit_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_agent_before_submit_ns); }},
	{"perf_agent_after_submit_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_agent_after_submit_ns); }},
	{"perf_collector_receive_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.e->perf_collector_receive_ns); }},
	{"perf_mongo_before_insert_ns", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.mongo_before_insert_ns); }},
#endif
	{"pid", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, c.e->pid); }},
	{"tid", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, c.e->tid); }},
	{"ret_code", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, c.e->ret_code); }},
	{"stmt_type_value", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, c.e->stmt_type); }},
	{"stmt_type", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, stmt_type_to_string(c.e->stmt_type)); }},
	{"plan_type_value", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int)c.e->plan_type); }},
	{"plan_type", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, plan_type_to_string(c.e->plan_type)); }},
	{"trans_status_value", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int)c.e->trans_status); }},
	{"trans_status", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, trans_status_to_ob_sql_audit_string_for_mongo(c.e->trans_status)); }},
	{"fragment_flags", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.e->fragment_flags); }},
	{"next_fragment_field", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.e->next_fragment_field); }},
	{"user_client_ip", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, format_ob_addr_for_mongo(c.e->user_client_ip, sizeof(c.e->user_client_ip)).c_str()); }},
	{"client_ip", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, format_ob_addr_for_mongo(c.e->client_ip, sizeof(c.e->client_ip)).c_str()); }},
	{"server_ip", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, c.indexed_server_ip); }},
	{"sql_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, c.e->sql_id); }},
	{"trace_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, format_trace_id_for_mongo(c.e->trace_id).c_str()); }},
	{"user_name", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_user_name(c.e), c.e->user_name_len); }},
	{"proxy_user_name", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_proxy_user_name(c.e), c.e->proxy_user_name_len); }},
	{"tenant_name", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_tenant_name(c.e), c.e->tenant_name_len); }},
	{"db_name", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_db_name(c.e), c.e->db_name_len); }},
	{"query_sql", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_query_sql(c.e), c.e->query_sql_payload_len); }},
	{"params_value", +[](bson_t *d, const char *k, const append_ctx &c) { append_text(d, k, event_params_value(c.e), c.e->params_value_payload_len); }},
	{"agent_id", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_UTF8(d, k, c.agent_id); }},
	{"ingest_time", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_DATE_TIME(d, k, c.ingest_time_ms); }},
	{"record_size", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT32(d, k, (int32_t)c.parsed->size); }},
	{"record_offset", +[](bson_t *d, const char *k, const append_ctx &c) { BSON_APPEND_INT64(d, k, (int64_t)c.parsed->offset); }},
};

static append_fn find_appender(const char *full_name)
{
	for (const field_appender &fa : kFieldAppenders)
		if (strcmp(fa.full_name, full_name) == 0)
			return fa.fn;
	return nullptr;
}

static bool append_event_doc(bson_t *doc, const std::vector<emit_entry> &plan, int schema_version,
				     const std::string &agent_id, const std::string &request_server_ip,
				     const audit_ingest::parsed_audit_event &parsed, int64_t ingest_time_ms,
				     unsigned long long mongo_before_insert_ns = 0)
{
	const event *e = parsed.record;
	std::string event_server_ip = format_ob_addr_for_mongo(e->server_ip, sizeof(e->server_ip));
	std::string indexed_server_ip = event_server_ip.empty() ? request_server_ip : event_server_ip;

	bson_init(doc);
	// Top-level ingest_time is kept for MongoDB TTL; schema-driven fields below
	// may also include ingest_time under a compact numeric key for readers.
	BSON_APPEND_DATE_TIME(doc, "ingest_time", ingest_time_ms);

	append_ctx ctx;
	ctx.e = e;
	ctx.agent_id = agent_id.c_str();
	ctx.indexed_server_ip = indexed_server_ip.c_str();
	ctx.parsed = &parsed;
	ctx.ingest_time_ms = ingest_time_ms;
	ctx.mongo_before_insert_ns = mongo_before_insert_ns;

	for (const emit_entry &entry : plan)
		entry.fn(doc, entry.key.c_str(), ctx);
	return true;
}

static bool duplicate_only(const bson_t *reply)
{
	bson_iter_t iter;
	if (!bson_iter_init_find(&iter, reply, "writeErrors") || !BSON_ITER_HOLDS_ARRAY(&iter))
		return false;
	const uint8_t *data = nullptr;
	uint32_t len = 0;
	bson_iter_array(&iter, &len, &data);
	bson_t array;
	if (!bson_init_static(&array, data, len))
		return false;
	bson_iter_t child;
	if (!bson_iter_init(&child, &array))
		return false;
	while (bson_iter_next(&child)) {
		bson_t err_doc;
		uint32_t doc_len = 0;
		const uint8_t *doc_data = nullptr;
		bson_iter_document(&child, &doc_len, &doc_data);
		if (!bson_init_static(&err_doc, doc_data, doc_len))
			return false;
		bson_iter_t code_iter;
		if (!bson_iter_init_find(&code_iter, &err_doc, "code") || bson_iter_int32(&code_iter) != MONGOC_ERROR_DUPLICATE_KEY)
			return false;
	}
	return true;
}

static bool parse_write_concern_w(const std::string &value, int32_t *w)
{
	if (!w || value.empty())
		return false;
	const char *text = value.c_str();
	if ((text[0] == 'w' || text[0] == 'W') && text[1] != '\0')
		text++;
	for (const char *p = text; *p; p++) {
		if (!std::isdigit(static_cast<unsigned char>(*p)))
			return false;
	}
	*w = (int32_t)std::strtol(text, nullptr, 10);
	return true;
}

static mongoc_write_concern_t *build_write_concern(const std::string &value, unsigned int wtimeout_ms)
{
	mongoc_write_concern_t *wc = mongoc_write_concern_new();
	int32_t w = 0;
	if (parse_write_concern_w(value, &w)) {
		mongoc_write_concern_set_w(wc, w);
	} else if (value == "majority") {
		mongoc_write_concern_set_wmajority(wc, (int32_t)wtimeout_ms);
	} else if (!value.empty()) {
		mongoc_write_concern_set_wtag(wc, value.c_str());
	}
	mongoc_write_concern_set_wtimeout(wc, (int32_t)wtimeout_ms);
	return wc;
}

#endif

MongoSink::MongoSink()
	: impl_(new Impl())
{
}

MongoSink::~MongoSink()
{
	stop();
	delete impl_;
}

bool MongoSink::start(const mongodb_config &config, std::string *error)
{
#if !HAVE_MONGOC
	if (error)
		*error = "libmongoc headers are not available; install libmongoc-dev libbson-dev";
	return false;
#else
	if (impl_->started)
		return true;

	audit_schema schema;
	if (!load_audit_schema_file(config.schema_file_path, &schema, error))
		return false;

	// Resolve the file's fields against the appender registry into an ordered
	// emit plan, and index the field names for building the unique index.
	std::unordered_map<std::string, std::string> full_to_key;
	std::vector<emit_entry> plan;
	plan.reserve(schema.fields.size());
	for (const auto &f : schema.fields) {
		append_fn fn = find_appender(f.second.c_str());
		if (!fn) {
			if (error)
				*error = "schema field has no writer support: " + f.second;
			return false;
		}
		plan.push_back(emit_entry{f.first, fn});
		full_to_key[f.second] = f.first;
	}

	impl_->config = config;
	impl_->emit_plan = std::move(plan);
	impl_->schema_version = schema.version;
	mongoc_init();
	impl_->write_concern = build_write_concern(config.write_concern, config.write_concern_wtimeout_ms);

	bson_error_t bson_error;
	mongoc_uri_t *uri = mongoc_uri_new_with_error(config.uri.c_str(), &bson_error);
	if (!uri) {
		if (error)
			*error = bson_error.message;
		return false;
	}

	mongoc_uri_set_appname(uri, config.app_name.c_str());
	mongoc_uri_set_option_as_int32(uri, MONGOC_URI_CONNECTTIMEOUTMS, config.connect_timeout_ms);
	mongoc_uri_set_option_as_int32(uri, MONGOC_URI_SERVERSELECTIONTIMEOUTMS, config.server_selection_timeout_ms);
	mongoc_uri_set_option_as_int32(uri, MONGOC_URI_SOCKETTIMEOUTMS, config.socket_timeout_ms);
	mongoc_uri_set_option_as_int32(uri, MONGOC_URI_MAXPOOLSIZE, config.pool_max_size);

	impl_->pool = mongoc_client_pool_new(uri);
	mongoc_uri_destroy(uri);
	if (!impl_->pool) {
		if (error)
			*error = "failed to create MongoDB client pool";
		return false;
	}

	mongoc_client_t *client = mongoc_client_pool_pop(impl_->pool);
	if (!client) {
		if (error)
			*error = "failed to pop MongoDB client";
		mongoc_client_pool_destroy(impl_->pool);
		impl_->pool = nullptr;
		return false;
	}

	bson_t ping;
	bson_t reply;
	bson_init(&ping);
	BSON_APPEND_INT32(&ping, "ping", 1);
	bool ok = mongoc_client_command_simple(client, "admin", &ping, nullptr, &reply, &bson_error);
	bson_destroy(&reply);
	bson_destroy(&ping);
	if (!ok) {
		if (error)
			*error = bson_error.message;
		mongoc_client_pool_push(impl_->pool, client);
		mongoc_client_pool_destroy(impl_->pool);
		impl_->pool = nullptr;
		return false;
	}

		if (!ensure_unique_index(client, config, full_to_key, error)) {
			mongoc_client_pool_push(impl_->pool, client);
			mongoc_client_pool_destroy(impl_->pool);
			impl_->pool = nullptr;
			return false;
		}

		if (!ensure_ttl_index(client, config.database, config.collection, "ingest_time", config.event_ttl_days, error) ||
		    !ensure_ttl_index(client, config.database, config.metrics_collection, "ts", config.metrics_ttl_days, error)) {
			mongoc_client_pool_push(impl_->pool, client);
			mongoc_client_pool_destroy(impl_->pool);
			impl_->pool = nullptr;
			return false;
		}

		if (!ensure_secondary_indexes(client, config, full_to_key, error)) {
			mongoc_client_pool_push(impl_->pool, client);
			mongoc_client_pool_destroy(impl_->pool);
			impl_->pool = nullptr;
			return false;
		}

		if (!ensure_schema_dict(client, config, schema, error)) {
		mongoc_client_pool_push(impl_->pool, client);
		mongoc_client_pool_destroy(impl_->pool);
		impl_->pool = nullptr;
		return false;
	}

	mongoc_client_pool_push(impl_->pool, client);
	impl_->started = true;
	return true;
#endif
}

void MongoSink::stop()
{
#if HAVE_MONGOC
	if (impl_->write_concern) {
		mongoc_write_concern_destroy(impl_->write_concern);
		impl_->write_concern = nullptr;
	}
	if (impl_->pool) {
		mongoc_client_pool_destroy(impl_->pool);
		impl_->pool = nullptr;
	}
	if (impl_->started)
		mongoc_cleanup();
#endif
	impl_->started = false;
}

bool MongoSink::enabled() const
{
	return impl_->started;
}

bool MongoSink::insert_events(const std::string &agent_id, const std::string &server_ip,
				      const std::vector<audit_ingest::parsed_audit_event> &events,
				      unsigned long long *accepted_records, unsigned long long *accepted_bytes,
				      std::string *error
#if AUDIT_GRPC_TIMING_ENABLED
				      , mongodb_insert_stats *insert_stats
#endif
				      )
{
	if (accepted_records)
		*accepted_records = 0;
	if (accepted_bytes)
		*accepted_bytes = 0;
	if (events.empty())
		return true;
#if !HAVE_MONGOC
	if (error)
		*error = "libmongoc headers are not available; install libmongoc-dev libbson-dev";
	return false;
#else
	if (!impl_->started || !impl_->pool) {
		if (error)
			*error = "MongoDB sink is not started";
		return false;
	}

#if AUDIT_GRPC_TIMING_ENABLED
	mongodb_insert_stats local_stats;
	mongodb_insert_stats *stats = insert_stats ? insert_stats : &local_stats;
	*stats = mongodb_insert_stats();
	const unsigned long long total_start_ns = AUDIT_TIMING_NOW();
#endif
	mongoc_client_t *client = mongoc_client_pool_pop(impl_->pool);
	if (!client) {
		if (error)
			*error = "failed to pop MongoDB client";
		return false;
	}

	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, impl_->config.database.c_str(), impl_->config.collection.c_str());
	if (!collection) {
		mongoc_client_pool_push(impl_->pool, client);
		if (error)
			*error = "failed to get MongoDB collection";
		return false;
	}

	std::vector<bson_t> docs(events.size());
	std::vector<const bson_t *> doc_ptrs(events.size());
	unsigned long long bytes = 0;
	const int64_t ingest_time_ms = (int64_t)time(nullptr) * 1000;
#if AUDIT_PERF_FIELDS_ENABLED
	unsigned long long mongo_before_insert_ns = monotonic_ns();
#endif
#if AUDIT_GRPC_TIMING_ENABLED
	const unsigned long long build_docs_start_ns = AUDIT_TIMING_NOW();
#endif
	for (size_t i = 0; i < events.size(); i++) {
		bson_init(&docs[i]);
#if AUDIT_PERF_FIELDS_ENABLED
		append_event_doc(&docs[i], impl_->emit_plan, impl_->schema_version, agent_id, server_ip, events[i], ingest_time_ms, mongo_before_insert_ns);
#else
		append_event_doc(&docs[i], impl_->emit_plan, impl_->schema_version, agent_id, server_ip, events[i], ingest_time_ms);
#endif
		doc_ptrs[i] = &docs[i];
		bytes += events[i].size;
	}
#if AUDIT_GRPC_TIMING_ENABLED
	stats->build_docs_ns = AUDIT_TIMING_NOW() - build_docs_start_ns;
#endif

	bson_t opts;
	bson_error_t bson_error;
	bson_init(&opts);
	BSON_APPEND_BOOL(&opts, "ordered", impl_->config.ordered_insert);
	if (impl_->write_concern)
		mongoc_write_concern_append(impl_->write_concern, &opts);
	const unsigned int max_records = impl_->config.bulk_max_records;
	const unsigned long long max_bytes = impl_->config.bulk_max_bytes;
	bool accepted = true;
	for (size_t start = 0; start < doc_ptrs.size();) {
		size_t end = start;
		unsigned long long chunk_bytes = 0;
		while (end < doc_ptrs.size()) {
			if (end > start) {
				if (max_records && (end - start) >= max_records)
					break;
				if (max_bytes && chunk_bytes + events[end].size > max_bytes)
					break;
			}
			chunk_bytes += events[end].size;
			end++;
		}
		bson_t reply;
#if AUDIT_GRPC_TIMING_ENABLED
		const unsigned long long insert_many_start_ns = AUDIT_TIMING_NOW();
#endif
		bool ok = mongoc_collection_insert_many(collection, doc_ptrs.data() + start, end - start, &opts, &reply, &bson_error);
#if AUDIT_GRPC_TIMING_ENABLED
		stats->insert_many_ns += AUDIT_TIMING_NOW() - insert_many_start_ns;
#endif
		bool chunk_accepted = ok || duplicate_only(&reply);
		if (!chunk_accepted && error)
			*error = bson_error.message;
		bson_destroy(&reply);
		if (!chunk_accepted) {
			accepted = false;
			break;
		}
		start = end;
	}
#if AUDIT_GRPC_TIMING_ENABLED
	stats->total_ns = AUDIT_TIMING_NOW() - total_start_ns;
#endif

	bson_destroy(&opts);
	for (bson_t &doc : docs)
		bson_destroy(&doc);
	mongoc_collection_destroy(collection);
	mongoc_client_pool_push(impl_->pool, client);

	if (!accepted)
		return false;
	if (accepted_records)
		*accepted_records = events.size();
	if (accepted_bytes)
		*accepted_bytes = bytes;
	return true;
#endif
}

static int64_t unix_ms_now()
{
	return (int64_t)time(nullptr) * 1000;
}

bool MongoSink::insert_agent_metrics(const audit_agent_accounting_snapshot &snapshot, std::string *error)
{
#if !HAVE_MONGOC
	if (error)
		*error = "libmongoc headers are not available; install libmongoc-dev libbson-dev";
	return false;
#else
	if (!impl_->started || !impl_->pool) {
		if (error)
			*error = "MongoDB sink is not started";
		return false;
	}
	mongoc_client_t *client = mongoc_client_pool_pop(impl_->pool);
	if (!client) {
		if (error)
			*error = "failed to pop MongoDB client";
		return false;
	}
	mongoc_collection_t *collection = mongoc_client_get_collection(client, impl_->config.database.c_str(), impl_->config.metrics_collection.c_str());
	if (!collection) {
		mongoc_client_pool_push(impl_->pool, client);
		if (error)
			*error = "failed to get MongoDB metrics collection";
		return false;
	}
	bson_t doc;
	bson_init(&doc);
	BSON_APPEND_DATE_TIME(&doc, "ts", snapshot.report_unix_ms ? (int64_t)snapshot.report_unix_ms : unix_ms_now());
	BSON_APPEND_UTF8(&doc, "source_type", "agent");
	BSON_APPEND_UTF8(&doc, "source_id", snapshot.source_id.c_str());
	BSON_APPEND_UTF8(&doc, "server_ip", snapshot.server_ip.c_str());
	BSON_APPEND_INT64(&doc, "process_start_unix_ms", (int64_t)snapshot.process_start_unix_ms);
	BSON_APPEND_INT64(&doc, "sequence", (int64_t)snapshot.sequence);
	BSON_APPEND_INT64(&doc, "ob_audit_seen_records", (int64_t)snapshot.ob_audit_seen_records);
	BSON_APPEND_INT64(&doc, "ringbuf_lost_records", (int64_t)snapshot.ringbuf_lost_records);
	BSON_APPEND_INT64(&doc, "agent_received_records", (int64_t)snapshot.agent_received_records);
	BSON_APPEND_INT64(&doc, "pending_lost_records", (int64_t)snapshot.pending_lost_records);
	BSON_APPEND_INT64(&doc, "send_enqueue_lost_records", (int64_t)snapshot.send_enqueue_lost_records);
	BSON_APPEND_INT64(&doc, "collector_rejected_records", (int64_t)snapshot.collector_rejected_records);
	BSON_APPEND_INT64(&doc, "collector_queue_full_records", (int64_t)snapshot.collector_queue_full_records);
	BSON_APPEND_INT64(&doc, "upload_retry_exhausted_records", (int64_t)snapshot.upload_retry_exhausted_records);
	BSON_APPEND_INT64(&doc, "agent_lost_records", (int64_t)snapshot.agent_lost_records);
	BSON_APPEND_INT64(&doc, "sender_accepted_records", (int64_t)snapshot.sender_accepted_records);
	BSON_APPEND_INT64(&doc, "delivered_records", (int64_t)snapshot.delivered_records);
	BSON_APPEND_INT64(&doc, "acknowledged_records", (int64_t)snapshot.acknowledged_records);
	BSON_APPEND_INT64(&doc, "pending_inflight_records", (int64_t)snapshot.pending_inflight_records);
	BSON_APPEND_INT64(&doc, "sender_inflight_records", (int64_t)snapshot.sender_inflight_records);
	BSON_APPEND_INT64(&doc, "inflight_records", (int64_t)snapshot.inflight_records);
	bson_error_t bson_error;
	bool ok = mongoc_collection_insert_one(collection, &doc, nullptr, nullptr, &bson_error);
	if (!ok && error)
		*error = bson_error.message;
	bson_destroy(&doc);
	mongoc_collection_destroy(collection);
	mongoc_client_pool_push(impl_->pool, client);
	return ok;
#endif
}

bool MongoSink::insert_collector_metrics(const audit_collector_accounting_snapshot &snapshot, std::string *error)
{
#if !HAVE_MONGOC
	if (error)
		*error = "libmongoc headers are not available; install libmongoc-dev libbson-dev";
	return false;
#else
	if (!impl_->started || !impl_->pool) {
		if (error)
			*error = "MongoDB sink is not started";
		return false;
	}
	mongoc_client_t *client = mongoc_client_pool_pop(impl_->pool);
	if (!client) {
		if (error)
			*error = "failed to pop MongoDB client";
		return false;
	}
	mongoc_collection_t *collection = mongoc_client_get_collection(client, impl_->config.database.c_str(), impl_->config.metrics_collection.c_str());
	if (!collection) {
		mongoc_client_pool_push(impl_->pool, client);
		if (error)
			*error = "failed to get MongoDB metrics collection";
		return false;
	}
	bson_t doc;
	bson_init(&doc);
	BSON_APPEND_DATE_TIME(&doc, "ts", snapshot.report_unix_ms ? (int64_t)snapshot.report_unix_ms : unix_ms_now());
	BSON_APPEND_UTF8(&doc, "source_type", "collector");
	BSON_APPEND_UTF8(&doc, "source_id", snapshot.source_id.c_str());
	BSON_APPEND_UTF8(&doc, "listen_addr", snapshot.listen_addr.c_str());
	BSON_APPEND_INT64(&doc, "process_start_unix_ms", (int64_t)snapshot.process_start_unix_ms);
	BSON_APPEND_INT64(&doc, "sequence", (int64_t)snapshot.sequence);
	BSON_APPEND_INT64(&doc, "accepted_records", (int64_t)snapshot.accepted_records);
	BSON_APPEND_INT64(&doc, "rejected_records", (int64_t)snapshot.rejected_records);
	BSON_APPEND_INT64(&doc, "persisted_records", (int64_t)snapshot.persisted_records);
	BSON_APPEND_INT64(&doc, "db_failed_lost_records", (int64_t)snapshot.db_failed_lost_records);
	BSON_APPEND_INT64(&doc, "inflight_records", (int64_t)snapshot.inflight_records);
	bson_error_t bson_error;
	bool ok = mongoc_collection_insert_one(collection, &doc, nullptr, nullptr, &bson_error);
	if (!ok && error)
		*error = bson_error.message;
	bson_destroy(&doc);
	mongoc_collection_destroy(collection);
	mongoc_client_pool_push(impl_->pool, client);
	return ok;
#endif
}
