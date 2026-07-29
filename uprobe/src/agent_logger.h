// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef AGENT_LOGGER_H
#define AGENT_LOGGER_H

bool agent_log_init(const char *path);
void agent_log_close();
void agent_log_info(const char *fmt, ...);
void agent_log_error(const char *fmt, ...);

#endif /* AGENT_LOGGER_H */
