// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <cstddef>
#include <cstdio>

#include "uprobe.h"

#define PRINT_FIELD(type, field) \
	printf("%-24s offset=%4zu size=%4zu\n", #field, offsetof(type, field), sizeof(((type *)0)->field))

int main()
{
	printf("sizeof(ob_trace_id_raw) = %zu\n", sizeof(ob_trace_id_raw));
	printf("sizeof(event)           = %zu\n\n", sizeof(event));

	PRINT_FIELD(event, pid);
	PRINT_FIELD(event, tid);
	PRINT_FIELD(event, comm);
	PRINT_FIELD(event, user_id);
	PRINT_FIELD(event, tenant_id);
	PRINT_FIELD(event, effective_tenant_id);
	PRINT_FIELD(event, session_id);
	PRINT_FIELD(event, proxy_session_id);
	PRINT_FIELD(event, db_id);
	PRINT_FIELD(event, affected_rows);
	PRINT_FIELD(event, return_rows);
	PRINT_FIELD(event, transaction_hash);
	PRINT_FIELD(event, request_id);
	PRINT_FIELD(event, ret_code);
	PRINT_FIELD(event, request_timestamp);
	PRINT_FIELD(event, elapsed_time);
	PRINT_FIELD(event, execute_time);
	PRINT_FIELD(event, query_sql_len);
	PRINT_FIELD(event, params_value_len);
	PRINT_FIELD(event, stmt_type);
	PRINT_FIELD(event, plan_type);
	PRINT_FIELD(event, trans_status);
	PRINT_FIELD(event, fragment_flags);
	PRINT_FIELD(event, next_fragment_field);
	PRINT_FIELD(event, user_name);
	PRINT_FIELD(event, proxy_user_name);
	PRINT_FIELD(event, tenant_name);
	PRINT_FIELD(event, user_client_ip);
	PRINT_FIELD(event, client_ip);
	PRINT_FIELD(event, db_name);
	PRINT_FIELD(event, sql_id);
	PRINT_FIELD(event, trace_id);
	PRINT_FIELD(event, query_sql);
	PRINT_FIELD(event, params_value);

	return 0;
}
