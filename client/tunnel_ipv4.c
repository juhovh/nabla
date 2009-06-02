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

/* Uses the following variables from endpoint_t struct:
 *   local_ipv4   - Local IPv4 address for the tunnel interface 
 *   local_prefix - The netmask prefix length of the IPv4 address
 *   remote_ipv4  - Remote IPv4 address of the server (if type v4v4)
 *   remote_ipv6  - Remote IPv6 address of the server (if type v4v6)
 *   local_mtu    - (optional) maximum transfer unit
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
	unsigned int netmask;
	int family;
};

static const char routerhw[] = { 0x00, 0x01, 0x23, 0x45, 0x67, 0x89 };

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

	memcpy(buf, tapcfg_iface_get_hwaddr(data->tapcfg, NULL), 6);
	memcpy(buf+6, routerhw, 6);
	buf[12] = 0x08;
	buf[13] = 0x00;

	logger_log(tunnel->logger, LOG_INFO, "Starting reader thread\n");

	do {
		fd_set rfds;
		struct timeval tv;

		struct sockaddr_storage saddr;
		socklen_t socklen;
		int srcmatch;

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
		saddr.ss_family = data->family;
		if (data->family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *) &saddr;
			sin->sin_addr.s_addr = htonl(INADDR_ANY);
		} else if (data->family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &saddr;
			sin6->sin6_addr = in6addr_any;
		}

		socklen = sizeof(saddr);
		ret = recvfrom(data->fd, (char *) (buf+14), sizeof(buf)-14, 0,
			       (struct sockaddr *) &saddr, &socklen);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error reading packet: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		} else if (ret == 0) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Disconnected from the server\n");
			break;
		}

		logger_log(tunnel->logger, LOG_DEBUG,
			   "Read packet of size %d from %d.%d.%d.%d\n",
			   ret, buf[26], buf[27], buf[28], buf[29]);

		if (data->family != saddr.ss_family) {
			logger_log(tunnel->logger, LOG_NOTICE,
			           "Discarding packet from incorrect family\n");
			goto read_loop;
		}

		srcmatch = 0;
		if (data->family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *) &saddr;
			srcmatch = (sin->sin_addr.s_addr == tunnel->endpoint.remote_ipv4.s_addr);
		} else if (data->family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &saddr;
			srcmatch = !memcmp(&sin6->sin6_addr,
			                   &tunnel->endpoint.remote_ipv6,
			                   sizeof(sin6->sin6_addr));
		}
		if (!srcmatch) {
			logger_log(tunnel->logger, LOG_NOTICE,
				   "Discarding packet from incorrect host\n");
			goto read_loop;
		}

		ret = tapcfg_write(data->tapcfg, buf, ret+14);
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

	logger_log(tunnel->logger, LOG_INFO,
	           "Finished reader thread\n");

	return 0;
}

static THREAD_RETVAL
writer_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	tunnel_data_t *data;
	const char *localhw;
	unsigned char buf[4096];
	int running;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	localhw = tapcfg_iface_get_hwaddr(data->tapcfg, NULL);
	assert(localhw);

	logger_log(tunnel->logger, LOG_INFO, "Starting writer thread\n");

	do {
		int buflen, type;

		if (!tapcfg_wait_readable(data->tapcfg, tunnel->waitms))
			goto write_loop;

		buflen = tapcfg_read(data->tapcfg, buf, sizeof(buf));
		type = buf[12] << 8 | buf[13];

		if (type == 0x0806) {
			struct in_addr ipaddr, localip;

			/* Incoming ARP request */
			if (buf[14] != 0x00 || buf[15] != 0x01 || // Hardware type: Ethernet
			buf[16] != 0x08 || buf[17] != 0x00 || // Protocol type: IP
			buf[18] != 0x06 || buf[19] != 0x04 || // Hw size: 6, Proto size: 4
			buf[20] != 0x00 || buf[21] != 0x01) { // Opcode: request
				/* Ignore invalid ARP packet */
				logger_log(tunnel->logger, LOG_WARNING,
				           "ARP request packet invalid\n");
				goto write_loop;
			}

			if (memcmp(buf+6, localhw, 6)) {
				logger_log(tunnel->logger, LOG_NOTICE,
				           "ARP coming from unknown device\n");
				goto write_loop;
			}

			memcpy(buf, buf+6, 6);
			memcpy(buf+6, routerhw, 6);

			memcpy(&ipaddr, buf+38, 4);
			localip = tunnel->endpoint.local_ipv4;
			if ((ipaddr.s_addr == localip.s_addr)) {
				/* Detecting for duplicate address, ignore */
				goto write_loop;
			}
			if ((ipaddr.s_addr ^ localip.s_addr) & data->netmask) {
				logger_log(tunnel->logger, LOG_WARNING,
				           "Target IP of ARP not available\n");
				goto write_loop;
			}

			memcpy(buf+32, buf+22, 10);
			memcpy(buf+22, routerhw, 6);
			memcpy(buf+28, &ipaddr, 4);

			/* Change opcode type into reply */
			buf[21] = 0x02;

			logger_log(tunnel->logger, LOG_INFO,
			           "Replied to an ARP request\n");
			tapcfg_write(data->tapcfg, buf, buflen);
		} else if (type == 0x800) {
			const char broadcasthw[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			const char multicasthw[] = { 0x01, 0x00, 0x5e };

			fd_set wfds;
			struct sockaddr_storage saddr;
			socklen_t saddrlen;
			int ret;

			if (memcmp(buf, routerhw, 6) &&
			    memcmp(buf, broadcasthw, 6) &&
			    memcmp(buf, multicasthw, 3)) {
				logger_log(tunnel->logger, LOG_NOTICE,
					   "Found an IPv4 packet to other host %d.%d.%d.%d\n",
					   buf[30], buf[31], buf[32], buf[33]);
				goto write_loop;
			}

			memset(&saddr, 0, sizeof(saddr));
			saddr.ss_family = data->family;
			if (data->family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *) &saddr;
				sin->sin_addr = tunnel->endpoint.remote_ipv4;
				saddrlen = sizeof(struct sockaddr_in);
			} else if (data->family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &saddr;
				sin6->sin6_addr = tunnel->endpoint.remote_ipv6;
				saddrlen = sizeof(struct sockaddr_in6);
			}

			FD_ZERO(&wfds);
			FD_SET(data->fd, &wfds);
			ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
			if (ret == -1) {
				logger_log(tunnel->logger, LOG_ERR,
					   "Error when selecting for fd: %s (%d)\n",
					   strerror(GetLastError()), GetLastError());
				break;
			}

			ret = sendto(data->fd, (char *) (buf+14), buflen-14, 0,
				     (struct sockaddr *) &saddr, saddrlen);
			if (ret <= 0) {
				logger_log(tunnel->logger, LOG_ERR,
					   "Error writing to socket: %s (%d)\n",
					   strerror(GetLastError()), GetLastError());
				break;
			}

			logger_log(tunnel->logger, LOG_DEBUG,
				   "Wrote %d bytes to the server\n", ret);
		} else {
			logger_log(tunnel->logger, LOG_NOTICE,
			           "Packet of unhandled protocol type 0x%04x\n", type);
		}

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
	int family;
	int local_mtu;
	int sock;
	tapcfg_t *tapcfg;
	char address[INET_ADDRSTRLEN];
	unsigned int netmask;
	tunnel_data_t *data;
	int i, ret;

	assert(tunnel);
	endpoint = &tunnel->endpoint;

	switch (endpoint->type) {
	case TUNNEL_TYPE_V4V4:
		family = AF_INET;
		break;
	case TUNNEL_TYPE_V4V6:
		family = AF_INET6;
		break;
	default:
		return -1;
	}

	sock = socket(family, SOCK_RAW, IPPROTO_IPIP);
	if (sock < 0) {
		return -1;
	}

	assert(inet_ntop(AF_INET, &endpoint->local_ipv4,
	                 address, sizeof(address)));

	tapcfg = tapcfg_init();
	if (!tapcfg) {
		return -1;
	}

	ret = tapcfg_start(tapcfg, "ipv4tun", 1);
	if (ret < 0) {
		return -1;
	}

	ret = tapcfg_iface_set_ipv4(tapcfg, address,
	                            endpoint->local_prefix);
	if (ret < 0) {
		return -1;
	}

	if (endpoint->local_mtu <= 0) {
		local_mtu = 1460;
	} else {
		local_mtu = endpoint->local_mtu;
	}

	if (tapcfg_iface_set_mtu(tapcfg, local_mtu) < 0) {
		/* Error setting MTU not fatal if current MTU small enough */
		if (tapcfg_iface_get_mtu(tapcfg) > local_mtu) {
			closesocket(sock);
			tapcfg_destroy(tapcfg);
			return -1;
		}
	}

	netmask = 0;
	for (i=0; i<32; i++) {
		netmask <<= 1;
		if (endpoint->local_prefix-i > 0)
			netmask |= 1;
	}

	data = calloc(1, sizeof(tunnel_data_t));
	if (!data) {
		closesocket(sock);
		tapcfg_destroy(tapcfg);
		return -1;
	}
	data->fd = sock;
	data->tapcfg = tapcfg;
	data->netmask = htonl(netmask);
	data->family = family;
	tunnel->privdata = data;

	return 0;
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

	return 0;
}

static int
stop(tunnel_t *tunnel)
{
	tapcfg_t *tapcfg;

	assert(tunnel);
	assert(tunnel->privdata);

	tapcfg = tunnel->privdata->tapcfg;
	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_ALL_DOWN);

	return 0;
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
ipv4_initmod()
{
	return &module;
}

