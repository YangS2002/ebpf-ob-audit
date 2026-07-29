// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "mongodb_sink.h"
#include "../tools/audit_format.h"

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>

#if __has_include(<mongoc/mongoc.h>)
#define HAVE_MONGOC 1
#include <mongoc/mongoc.h>
#else
#define HAVE_MONGOC 0
#endif

struct MongoSink::Impl {
	mongodb_config config;
#if HAVE_MONGOC
	mongoc_client_pool_t *pool = nullptr;
#endif
	bool started = false;
	std::mutex mutex;
	std::condition_variable cv;
	unsigned int inflight = 0;
};

#if HAVE_MONGOC
static bool ensure_unique_index(mongoc_client_t *client, const mongodb_config &config, std::string *error)
{
	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, config.database.c_str(), config.collection.c_str());
	if (!collection) {
		if (error)
			*error = "failed to get MongoDB collection";
		return false;
	}

	bson_t keys;
	bson_init(&keys);
	BSON_APPEND_INT32(&keys, "tenant_id", 1);
	BSON_APPEND_INT32(&keys, "server_ip", 1);
	BSON_APPEND_INT32(&keys, "event_seq", 1);

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

static bool append_binary(bson_t *doc, const char *key, const void *data, unsigned int len)
{
	return bson_append_binary(doc, key, -1, BSON_SUBTYPE_BINARY, static_cast<const uint8_t *>(data), len);
}


static bool append_text(bson_t *doc, const char *key, const char *data, unsigned int len)
{
	return bson_append_utf8(doc, key, -1, data, (int)len);
}

static bool append_event_doc(bson_t *doc, const std::string &agent_id, const std::string &request_server_ip,
			     const audit_ingest::parsed_audit_event &parsed)
{
	const event *e = parsed.record;
	std::string event_server_ip = format_ob_addr_for_mongo(e->server_ip, sizeof(e->server_ip));
	std::string indexed_server_ip = event_server_ip.empty() ? request_server_ip : event_server_ip;
	bson_init(doc);
	BSON_APPEND_INT32(doc, "total_size", (int32_t)e->total_size);
	BSON_APPEND_INT32(doc, "record_type", (int32_t)e->record_type);
	BSON_APPEND_INT32(doc, "record_flags", (int32_t)e->record_flags);
	BSON_APPEND_INT64(doc, "event_seq", (int64_t)e->event_seq);
	BSON_APPEND_INT64(doc, "parent_event_seq", (int64_t)e->parent_event_seq);
	BSON_APPEND_INT64(doc, "next_fragment_seq", (int64_t)e->next_fragment_seq);
	BSON_APPEND_INT64(doc, "user_id", (int64_t)e->user_id);
	BSON_APPEND_INT64(doc, "tenant_id", (int64_t)e->tenant_id);
	BSON_APPEND_INT64(doc, "effective_tenant_id", (int64_t)e->effective_tenant_id);
	BSON_APPEND_INT64(doc, "session_id", (int64_t)e->session_id);
	BSON_APPEND_INT64(doc, "proxy_session_id", (int64_t)e->proxy_session_id);
	BSON_APPEND_INT64(doc, "db_id", (int64_t)e->db_id);
	BSON_APPEND_INT64(doc, "affected_rows", (int64_t)e->affected_rows);
	BSON_APPEND_INT64(doc, "return_rows", (int64_t)e->return_rows);
	BSON_APPEND_INT64(doc, "transaction_hash", (int64_t)e->transaction_hash);
	BSON_APPEND_INT64(doc, "request_id", (int64_t)e->request_id);
	BSON_APPEND_INT64(doc, "request_timestamp", e->request_timestamp);
	BSON_APPEND_INT64(doc, "elapsed_time", e->elapsed_time);
	BSON_APPEND_INT64(doc, "execute_time", e->execute_time);
	BSON_APPEND_INT64(doc, "query_sql_len", e->query_sql_len);
	BSON_APPEND_INT64(doc, "params_value_len", e->params_value_len);
	BSON_APPEND_INT32(doc, "user_name_len", (int32_t)e->user_name_len);
	BSON_APPEND_INT32(doc, "proxy_user_name_len", (int32_t)e->proxy_user_name_len);
	BSON_APPEND_INT32(doc, "tenant_name_len", (int32_t)e->tenant_name_len);
	BSON_APPEND_INT32(doc, "db_name_len", (int32_t)e->db_name_len);
	BSON_APPEND_INT32(doc, "query_sql_payload_len", (int32_t)e->query_sql_payload_len);
	BSON_APPEND_INT32(doc, "params_value_payload_len", (int32_t)e->params_value_payload_len);
	BSON_APPEND_INT32(doc, "pid", e->pid);
	BSON_APPEND_INT32(doc, "tid", e->tid);
	BSON_APPEND_INT32(doc, "ret_code", e->ret_code);
	BSON_APPEND_INT32(doc, "stmt_type_value", e->stmt_type);
	BSON_APPEND_UTF8(doc, "stmt_type", stmt_type_to_string(e->stmt_type));
	BSON_APPEND_INT32(doc, "plan_type_value", (int)e->plan_type);
	BSON_APPEND_UTF8(doc, "plan_type", plan_type_to_string(e->plan_type));
	BSON_APPEND_INT32(doc, "trans_status_value", (int)e->trans_status);
	BSON_APPEND_UTF8(doc, "trans_status", trans_status_to_ob_sql_audit_string_for_mongo(e->trans_status));
	BSON_APPEND_UTF8(doc, "trans_status_name", trans_status_to_ob_sql_audit_string_for_mongo(e->trans_status));
	BSON_APPEND_INT32(doc, "fragment_flags", (int32_t)e->fragment_flags);
	BSON_APPEND_INT32(doc, "next_fragment_field", (int32_t)e->next_fragment_field);
	BSON_APPEND_UTF8(doc, "user_client_ip", format_ob_addr_for_mongo(e->user_client_ip, sizeof(e->user_client_ip)).c_str());
	BSON_APPEND_UTF8(doc, "client_ip", format_ob_addr_for_mongo(e->client_ip, sizeof(e->client_ip)).c_str());
	BSON_APPEND_UTF8(doc, "server_ip", indexed_server_ip.c_str());
	BSON_APPEND_UTF8(doc, "event_server_ip", event_server_ip.c_str());
	BSON_APPEND_UTF8(doc, "request_server_ip", request_server_ip.c_str());
	BSON_APPEND_UTF8(doc, "sql_id", e->sql_id);
	BSON_APPEND_UTF8(doc, "trace_id", format_trace_id_for_mongo(e->trace_id).c_str());
	append_text(doc, "user_name", event_user_name(e), e->user_name_len);
	append_text(doc, "proxy_user_name", event_proxy_user_name(e), e->proxy_user_name_len);
	append_text(doc, "tenant_name", event_tenant_name(e), e->tenant_name_len);
	append_text(doc, "db_name", event_db_name(e), e->db_name_len);
	append_text(doc, "query_sql", event_query_sql(e), e->query_sql_payload_len);
	append_text(doc, "params_value", event_params_value(e), e->params_value_payload_len);
	append_binary(doc, "trace_id_raw", &e->trace_id, sizeof(e->trace_id));
	append_binary(doc, "user_client_ip_raw", e->user_client_ip, sizeof(e->user_client_ip));
	append_binary(doc, "client_ip_raw", e->client_ip, sizeof(e->client_ip));
	append_binary(doc, "server_ip_raw", e->server_ip, sizeof(e->server_ip));
	append_binary(doc, "raw_record", e, (unsigned int)parsed.size);
	BSON_APPEND_UTF8(doc, "agent_id", agent_id.c_str());
	BSON_APPEND_DATE_TIME(doc, "ingest_time", (int64_t)time(nullptr) * 1000);
	BSON_APPEND_INT32(doc, "record_size", (int32_t)parsed.size);
	BSON_APPEND_INT64(doc, "record_offset", (int64_t)parsed.offset);
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

	impl_->config = config;
	mongoc_init();

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

	if (!ensure_unique_index(client, config, error)) {
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
			      std::string *error)
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

	{
		std::unique_lock<std::mutex> lock(impl_->mutex);
		unsigned int limit = impl_->config.insert_concurrency ? impl_->config.insert_concurrency : 1;
		impl_->cv.wait(lock, [&] { return impl_->inflight < limit; });
		impl_->inflight++;
	}
	mongoc_client_t *client = mongoc_client_pool_pop(impl_->pool);
	if (!client) {
		{
			std::lock_guard<std::mutex> guard(impl_->mutex);
			if (impl_->inflight > 0)
				impl_->inflight--;
		}
		impl_->cv.notify_one();
		if (error)
			*error = "failed to pop MongoDB client";
		return false;
	}
	mongoc_collection_t *collection = mongoc_client_get_collection(
		client, impl_->config.database.c_str(), impl_->config.collection.c_str());
	if (!collection) {
		mongoc_client_pool_push(impl_->pool, client);
		{
			std::lock_guard<std::mutex> guard(impl_->mutex);
			if (impl_->inflight > 0)
				impl_->inflight--;
		}
		impl_->cv.notify_one();
		if (error)
			*error = "failed to get MongoDB collection";
		return false;
	}

	std::vector<bson_t *> docs(events.size());
	std::vector<const bson_t *> doc_ptrs(events.size());
	unsigned long long bytes = 0;
	for (size_t i = 0; i < events.size(); i++) {
		docs[i] = bson_new();
		append_event_doc(docs[i], agent_id, server_ip, events[i]);
		doc_ptrs[i] = docs[i];
		bytes += events[i].size;
	}

	bson_t opts;
	bson_t reply;
	bson_error_t bson_error;
	bson_init(&opts);
	BSON_APPEND_BOOL(&opts, "ordered", impl_->config.ordered_insert);
	bool ok = mongoc_collection_insert_many(collection, doc_ptrs.data(), doc_ptrs.size(), &opts, &reply, &bson_error);
	bool accepted = ok || duplicate_only(&reply);
	if (!accepted && error)
		*error = bson_error.message;

	bson_destroy(&reply);
	bson_destroy(&opts);
	for (bson_t *doc : docs)
		bson_destroy(doc);
	mongoc_collection_destroy(collection);
	mongoc_client_pool_push(impl_->pool, client);
	{
		std::lock_guard<std::mutex> guard(impl_->mutex);
		if (impl_->inflight > 0)
			impl_->inflight--;
	}
	impl_->cv.notify_one();

	if (!accepted)
		return false;
	if (accepted_records)
		*accepted_records = events.size();
	if (accepted_bytes)
		*accepted_bytes = bytes;
	return true;
#endif
}
