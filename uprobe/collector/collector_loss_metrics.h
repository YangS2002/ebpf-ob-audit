// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_LOSS_METRICS_H
#define COLLECTOR_LOSS_METRICS_H

#include <string>

#include "../src/audit_accounting.h"

void collector_loss_metrics_init(const std::string &collector_id, const std::string &listen_addr);
void collector_loss_metrics_accepted(unsigned long long records);
void collector_loss_metrics_rejected(unsigned long long records);
void collector_loss_metrics_persisted(unsigned long long records);
void collector_loss_metrics_db_retry_exhausted(unsigned long long records);
void collector_loss_metrics_flush();
audit_collector_accounting_snapshot collector_loss_metrics_snapshot();

#endif /* COLLECTOR_LOSS_METRICS_H */
