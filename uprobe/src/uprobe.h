/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UPROBE_H
#define __UPROBE_H

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN 64
#define MAX_IP_LEN 64
#define MAX_DB_NAME_LEN 128
#define MAX_SQL_ID_LEN 33 // 32 + 1 
#define MAX_TRACE_ID_LEN 128
#define MAX_SQL_LEN 512
#define MAX_PARAMS_VALUE_LEN 512

enum ObPhyPlanType
{
  OB_PHY_PLAN_UNINITIALIZED = 0,
  OB_PHY_PLAN_LOCAL,
  OB_PHY_PLAN_REMOTE,
  OB_PHY_PLAN_DISTRIBUTED,
  OB_PHY_PLAN_UNCERTAIN
};

enum ObTransStatus
{
  INVALID_STATUS = 0,
  TRANS_NOT_OPENED = 1,
  IMPLICIT_TRANS = 2,
  COMMIT_TRANS = 3,
};
struct ob_trace_id_raw {
    unsigned long long uval[4];
};

struct event {
	int pid;
	int tid;
	char comm[TASK_COMM_LEN];

	unsigned long long user_id; // int64_t 
	unsigned long long tenant_id; // int64_t
	unsigned long long effective_tenant_id; // int64_t
	unsigned long long session_id;// 虚拟表字段名：SID uint64_t
	unsigned long long proxy_session_id;// 虚拟表中没有这个字段，但是审计记录中有，proxy_session_id_ uint64_t
	unsigned long long db_id;// uint64_t
	unsigned long long affected_rows;// int64_t
	unsigned long long return_rows;// int64_t
	unsigned long long transaction_hash;// 虚拟表字段名：TX_ID, 审计记录成员变量名：trans_id_
	unsigned long long request_id;//

	int ret_code; //  status_ 成员变量
	// elapsed_time的成员变量receive_ts_ 。 exec_timestamp_.receive_ts_
	long long request_timestamp;// 虚拟表字段名：REQUEST_TIME   
	
	// 通过get_elapsed_time()成员函数调用计算得到
	// exec_timestamp_.receive_ts_
	// exec_timestamp_.executor_end_ts_
	// exec_timestamp_.multistmt_start_ts_
	// if (exec_timestamp_.multistmt_start_ts > 0)
	//     elapsed_time = exec_timestamp_.executor_end_ts - exec_timestamp_.multistmt_start_ts;
	// else
	//     elapsed_time = exec_timestamp_.executor_end_ts - exec_timestamp_.receive_ts;
	long long elapsed_time;//

	// 执行时间，sqlaudit record 记录非常详细的各阶段的执行时间在ObExecTimestamp中。成员变量名 ：exec_timestamp_
	long long execute_time; // 
	long long query_sql_len;
	long long params_value_len;

	int stmt_type; // enum:int_t 32 需要用户态解析，
	enum ObPhyPlanType plan_type; // 
	enum ObTransStatus trans_status;//

	char user_name[MAX_NAME_LEN];//
	char proxy_user_name[MAX_NAME_LEN];//  虚拟表字段名：PROXY_USER
	char tenant_name[MAX_NAME_LEN];//

	// user_client_ip，client_ip均不在记录中，可能需要从session的上下文中获取
	char user_client_ip[MAX_IP_LEN];// 
	char client_ip[MAX_IP_LEN];//

	// char server_ip[MAX_IP_LEN];// 可以本机获取
	char db_name[MAX_DB_NAME_LEN];//
	char sql_id[MAX_SQL_ID_LEN];//

	struct ob_trace_id_raw trace_id;//
	char query_sql[MAX_SQL_LEN];// 成员变量名:sql_
	char params_value[MAX_PARAMS_VALUE_LEN]; // PS协议中的参数值
};

#endif /* __UPROBE_H */
