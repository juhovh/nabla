/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009  Juho Vähä-Herttua
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "logger.h"

struct logger_s {
	int level;
	logger_callback_t callback;
};

logger_t *
logger_init()
{
	logger_t *logger;

	logger = calloc(1, sizeof(logger_t));
	if (!logger) {
		return NULL;
	}

	logger->level = LOG_INFO;
	logger->callback = NULL;

	return logger;
}

void
logger_set_level(logger_t *logger, int level)
{
	if (!logger)
		return;

	logger->level = level;
}

void
logger_set_callback(logger_t *logger, logger_callback_t callback) {
	if (!logger)
		return;

	logger->callback = callback;
}

void
logger_log(logger_t *logger, int level, const char *fmt, ...)
{
	char buffer[4096];
	va_list ap;

	if (!logger)
		return;

	if (level > logger->level)
		return;

	buffer[sizeof(buffer)-1] = '\0';
	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer)-1, fmt, ap);
	va_end(ap);

	if (logger->callback) {
		logger->callback(buffer);
	} else {
		fprintf(stderr, "%s", buffer);
	}
}

void
logger_destroy(logger_t *logger)
{
	free(logger);
}

