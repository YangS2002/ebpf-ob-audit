/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UPROBE_H
#define __UPROBE_H

#define TASK_COMM_LEN 16
#define MAX_SQL_LEN 512

struct event {
	int pid;
	int tid;
	long long sql_len;
	char comm[TASK_COMM_LEN];
	char sql[MAX_SQL_LEN];
};

#endif /* __UPROBE_H */
