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

/* Uses the following variables from endpoint_t struct:
 *   remote_ipv4 - IPv4 address of the remote server
 *   remote_port - UDP port of the remote server
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "compat.h"
#include "tapcfg.h"
#include "tunnel.h"


struct tunnel_data_s {
	int fd;
	tapcfg_t *tapcfg;
};

static THREAD_RETVAL
reader_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	tunnel_data_t *data;
	unsigned char buf[4096];
	int running;
	int ret;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	logger_log(tunnel->logger, LOG_INFO, "Starting reader thread\n");

	do {
		fd_set rfds;
		struct timeval tv;

		struct sockaddr_in saddr;
		socklen_t socklen;

		FD_ZERO(&rfds);
		FD_SET(data->fd, &rfds);

		tv.tv_sec = tunnel->waitms / 1000;
		tv.tv_usec = (tunnel->waitms % 1000) * 1000;
		ret = select(data->fd+1, &rfds, NULL, NULL, &tv);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error when selecting for fd: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		}

		if (!FD_ISSET(data->fd, &rfds))
			goto read_loop;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
		saddr.sin_port = htons(0);

		socklen = sizeof(saddr);
		ret = recvfrom(data->fd, (char *) buf, sizeof(buf), 0,
			       (struct sockaddr *) &saddr, &socklen);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error in receiving data: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		} else if (ret == 0) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Disconnected from the server\n");
			break;
		}

		if (saddr.sin_addr.s_addr != tunnel->endpoint.remote_ipv4.s_addr ||
		    ntohs(saddr.sin_port) != tunnel->endpoint.remote_port) {
			logger_log(tunnel->logger, LOG_NOTICE,
			           "Discarding packet from incorrect host\n");
			goto read_loop;
		}

		logger_log(tunnel->logger, LOG_DEBUG,
		           "Read %d bytes from the server\n", ret);

		/* Check for minimum Ethernet header length */
		if (ret < 14) {
			break;
		}

		/* Check that the frame type is IPv6 */
		if (buf[12] != 0x86 || buf[13] != 0xdd) {
			goto read_loop;
		}

		if (buf[0] != 0x33 || buf[1] != 0x33) {
			const char *hwaddr;
			hwaddr = tapcfg_iface_get_hwaddr(data->tapcfg, NULL);
			memcpy(buf, hwaddr, 6);
		}

		ret = tapcfg_write(data->tapcfg, buf, ret);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error writing packet\n");
			break;
		}

read_loop:
		MUTEX_LOCK(tunnel->run_mutex);
		running = tunnel->running;
		MUTEX_UNLOCK(tunnel->run_mutex);
	} while (running);

	MUTEX_LOCK(tunnel->run_mutex);
	tunnel->running = 0;
	MUTEX_UNLOCK(tunnel->run_mutex);

	logger_log(tunnel->logger, LOG_INFO, "Finished reader thread\n");

	return 0;
}

static THREAD_RETVAL
writer_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	tunnel_data_t *data;
	unsigned char buf[4096];
	int running;
	int ret;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	logger_log(tunnel->logger, LOG_INFO, "Starting writer thread\n");

	do {
		fd_set wfds;
		struct sockaddr_in saddr;
		int len, etherType;

		if (!tapcfg_wait_readable(data->tapcfg, tunnel->waitms))
			goto write_loop;

		len = tapcfg_read(data->tapcfg, buf, sizeof(buf));
		if (len <= 0) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error in tapcfg reading\n");
			break;
		}

		logger_log(tunnel->logger, LOG_DEBUG,
		           "Read %d bytes from the device\n", len);

		if (len < 14) {
			/* Not enough data for Ethernet header */
			break;
		}
		etherType = (buf[12] << 8) | buf[13];

		if (etherType == 0x8100 || etherType < 0x0800) {
			/* IEEE 802.1Q tagged frame or not Ethernet II */
			goto write_loop;
		}

		if (etherType != 0x86dd) {
			/* Not an IPv6 packet, so we can ignore it */
			goto write_loop;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr = tunnel->endpoint.remote_ipv4;
		saddr.sin_port = htons(tunnel->endpoint.remote_port);

		FD_ZERO(&wfds);
		FD_SET(data->fd, &wfds);
		ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error when selecting for fd: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		}

		ret = sendto(data->fd, (char *) buf, len, 0,
		             (struct sockaddr *) &saddr,
		             sizeof(saddr));
		if (ret <= 0) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error in writing to socket: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		}
		logger_log(tunnel->logger, LOG_DEBUG,
		           "Wrote %d bytes to the server\n", len);

write_loop:
		MUTEX_LOCK(tunnel->run_mutex);
		running = tunnel->running;
		MUTEX_UNLOCK(tunnel->run_mutex);
	} while (running);

	MUTEX_LOCK(tunnel->run_mutex);
	tunnel->running = 0;
	MUTEX_UNLOCK(tunnel->run_mutex);

	logger_log(tunnel->logger, LOG_INFO, "Finished writer thread\n");

	return 0;
}

static int
init(tunnel_t *tunnel)
{
	const endpoint_t *endpoint;
	int sock;
	tapcfg_t *tapcfg;
	tunnel_data_t *data;
	int ret;

	assert(tunnel);
	endpoint = &tunnel->endpoint;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		return -1;
	}

	tapcfg = tapcfg_init();
	if (!tapcfg) {
		return -1;
	}

	ret = tapcfg_start(tapcfg, "ipv6tun", 1);
	if (ret < 0) {
		return -1;
	}

	data = calloc(1, sizeof(tunnel_data_t));
	if (!data) {
		closesocket(sock);
		tapcfg_destroy(tapcfg);
		return 0;
	}
	data->fd = sock;
	data->tapcfg = tapcfg;
	tunnel->privdata = data;

	return 1;
}

static void
destroy(tunnel_t *tunnel)
{
	if (tunnel && tunnel->privdata) {
		closesocket(tunnel->privdata->fd);
		tapcfg_destroy(tunnel->privdata->tapcfg);
		free(tunnel->privdata);
	}
}

static int
start(tunnel_t *tunnel)
{
	tapcfg_t *tapcfg;

	assert(tunnel);
	assert(tunnel->privdata);

	tapcfg = tunnel->privdata->tapcfg;
	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_IPV4_UP);

	THREAD_CREATE(tunnel->reader, reader_thread, tunnel);
	THREAD_CREATE(tunnel->writer, writer_thread, tunnel);

	return 1;
}

static int
stop(tunnel_t *tunnel)
{
	tapcfg_t *tapcfg;

	assert(tunnel);
	assert(tunnel->privdata);

	tapcfg = tunnel->privdata->tapcfg;
	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_ALL_DOWN);

	return 1;
}

static tunnel_mod_t module =
{
	init,
	start,
	stop,
	NULL,
	destroy
};

const tunnel_mod_t *
ether_initmod()
{
	return &module;
}

