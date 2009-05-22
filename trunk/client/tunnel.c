/**
 *  NABLA - Automatic IP Tunneling and Connectivity
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
#include <string.h>
#include <assert.h>

#include "compat.h"
#include "threads.h"
#include "tunnel.h"

static THREAD_RETVAL
beater_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	int time_left;
	int running;

	assert(tunnel);
	assert(tunnel->tunmod);
	assert(tunnel->tunmod->beat);
	assert(tunnel->endpoint.beat_interval > 0);

	logger_log(tunnel->logger, LOG_INFO, "Starting beater thread\n");

	if (tunnel->endpoint.type == TUNNEL_TYPE_AYIYA) {
		/* Two extra beats for AYIYA to be bug-compatible with aiccu */
		tunnel->tunmod->beat(tunnel);
		tunnel->tunmod->beat(tunnel);
	} else if (tunnel->endpoint.type == TUNNEL_TYPE_HEARTBEAT) {
		/* One extra beat for heartbeat to be bug-compatible with aiccu */
		tunnel->tunmod->beat(tunnel);
	}

	time_left = 0;
	do {
		if (time_left <= 0) {
			logger_log(tunnel->logger, LOG_DEBUG,
			           "Sending beat signal to server\n");
			tunnel->tunmod->beat(tunnel);
			time_left = tunnel->endpoint.beat_interval*1000;
		}

		sleepms(tunnel->waitms);
		time_left -= tunnel->waitms;

		MUTEX_LOCK(tunnel->run_mutex);
		running = tunnel->running;
		MUTEX_UNLOCK(tunnel->run_mutex);
	} while (running);

	MUTEX_LOCK(tunnel->run_mutex);
	tunnel->running = 0;
	MUTEX_UNLOCK(tunnel->run_mutex);

	logger_log(tunnel->logger, LOG_INFO, "Finished beater thread\n");

	return 0;
}

tunnel_t *
tunnel_init(endpoint_t *endpoint)
{
	tunnel_t *tunnel;

	tunnel = calloc(1, sizeof(tunnel_t));
	if (!tunnel) {
		return NULL;
	}

	switch (endpoint->type) {
	case TUNNEL_TYPE_V4V6:
		tunnel->tunmod = v4v6_initmod();
		break;
	case TUNNEL_TYPE_ETHER:
		tunnel->tunmod = ether_initmod();
		break;
	case TUNNEL_TYPE_AYIYA:
		tunnel->tunmod = ayiya_initmod();
		break;
	case TUNNEL_TYPE_V6V4:
	case TUNNEL_TYPE_HEARTBEAT:
		tunnel->tunmod = v6v4_initmod();
		break;
	default:
		free(tunnel);
		return NULL;
	}
	tunnel->waitms = 100;
	tunnel->logger = logger_init();
	assert(tunnel->logger);

	tunnel->running = 0;
	tunnel->joined = 1;

	MUTEX_CREATE(tunnel->run_mutex);
	MUTEX_CREATE(tunnel->join_mutex);

	memcpy((endpoint_t *) &tunnel->endpoint, endpoint, sizeof(endpoint_t));

	if (tunnel->tunmod->init(tunnel) == -1) {
		tunnel_destroy(tunnel);
		return NULL;
	}

	return tunnel;
}

int
tunnel_start(tunnel_t *tunnel)
{
	assert(tunnel);

	MUTEX_LOCK(tunnel->run_mutex);
	MUTEX_LOCK(tunnel->join_mutex);
	if (tunnel->running) {
		MUTEX_UNLOCK(tunnel->join_mutex);
		MUTEX_UNLOCK(tunnel->run_mutex);
		return -1;
	}
	tunnel->running = 1;
	tunnel->joined = 0;

	if (tunnel->endpoint.beat_interval > 0) {
		THREAD_CREATE(tunnel->beater, beater_thread, tunnel);
	}

	if (tunnel->tunmod->start(tunnel) == -1) {
		if (tunnel->endpoint.beat_interval > 0) {
			THREAD_JOIN(tunnel->beater);
		}
		tunnel->running = 0;
		tunnel->joined = 1;
		MUTEX_UNLOCK(tunnel->join_mutex);
		MUTEX_UNLOCK(tunnel->run_mutex);
		return -1;
	}

	MUTEX_UNLOCK(tunnel->join_mutex);
	MUTEX_UNLOCK(tunnel->run_mutex);

	return 0;
}

int
tunnel_stop(tunnel_t *tunnel)
{
	assert(tunnel);

	MUTEX_LOCK(tunnel->run_mutex);
	tunnel->running = 0;

	/* join mutex should always be locked
	 * inside run mutex to avoid race conditions  */
	MUTEX_LOCK(tunnel->join_mutex);
	MUTEX_UNLOCK(tunnel->run_mutex);

	if (tunnel->joined) {
		MUTEX_UNLOCK(tunnel->join_mutex);
		return 0;
	}
	if (tunnel->endpoint.beat_interval > 0) {
		THREAD_JOIN(tunnel->beater);
	}
	THREAD_JOIN(tunnel->reader);
	THREAD_JOIN(tunnel->writer);
	tunnel->joined = 0;

	if (tunnel->tunmod->stop(tunnel) == -1) {
		/* Nothing to be done really, just report error */
		MUTEX_UNLOCK(tunnel->join_mutex);
		return -1;
	}

	MUTEX_UNLOCK(tunnel->join_mutex);

	return 0;
}

int
tunnel_running(tunnel_t *tunnel)
{
	int running;

	MUTEX_LOCK(tunnel->run_mutex);
	running = tunnel->running;
	MUTEX_UNLOCK(tunnel->run_mutex);

	return running;
}

void
tunnel_destroy(tunnel_t *tunnel)
{
	if (tunnel) {
		tunnel_stop(tunnel);

		tunnel->tunmod->destroy(tunnel);
		logger_destroy(tunnel->logger);

		MUTEX_DESTROY(tunnel->run_mutex);
		MUTEX_DESTROY(tunnel->join_mutex);
	}
	free(tunnel);
}

