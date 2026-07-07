// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

#define OB_AUDIT_SQL_PTR_OFF 328
#define OB_AUDIT_SQL_LEN_OFF 336

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 
} rb SEC(".maps");

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx)
{
	struct event *e;
	const void *audit_record;
	const char *sql = NULL;
	long long sql_len = 0;
	u64 id;

	audit_record = (const void *)PT_REGS_PARM2(ctx);
	if (!audit_record)
		return 0;

	// 读取审计记录中的SQL语句和长度
	bpf_probe_read_user(&sql, sizeof(sql), (const char *)audit_record + OB_AUDIT_SQL_PTR_OFF);
	bpf_probe_read_user(&sql_len, sizeof(sql_len), (const char *)audit_record + OB_AUDIT_SQL_LEN_OFF);
	if (!sql || sql_len <= 0)
		return 0;

	// 缓冲区预留，!e表示缓冲区满，当前审计记录会丢失
	// 检查是否还有一个entry的空间，一个entry就是一个event结构体的大小
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (u32)id;
	e->sql_len = sql_len;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->sql, sizeof(e->sql), sql);

	// 提交缓冲区
	bpf_ringbuf_submit(e, 0);
	return 0;
}
