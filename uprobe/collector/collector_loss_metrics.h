// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef COLLECTOR_LOSS_METRICS_H
#define COLLECTOR_LOSS_METRICS_H

#include <string>

void collector_loss_metrics_init(const std::string &collector_id, const std::string &listen_addr);
void collector_loss_metrics_accepted(unsigned long long records);
void collector_loss_metrics_persisted(unsigned long long records);
void collector_loss_metrics_db_queue_dropped(unsigned long long records);
void collector_loss_metrics_db_retry_exhausted(unsigned long long records);
void collector_loss_metrics_flush();

#endif /* COLLECTOR_LOSS_METRICS_H */
