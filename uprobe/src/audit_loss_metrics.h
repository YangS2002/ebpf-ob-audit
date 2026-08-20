// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AUDIT_LOSS_METRICS_H
#define AUDIT_LOSS_METRICS_H

struct audit_bpf_loss_stats {
	unsigned long long ob_audit_seen_records;
	unsigned long long ringbuf_full_dropped_records;
};

#endif /* AUDIT_LOSS_METRICS_H */
