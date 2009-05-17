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
 *   local_ipv4   - Local IPv4 address for the tunnel interface 
 *   local_prefix - The netmask prefix length of the IPv4 address
 *   remote_ipv6  - Remote IPv6 address of the server
 *   local_mtu    - (optional) maximum transfer unit
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "compat.h"
#include "tapcfg.h"
#include "tunnel.h"


struct tunnel_data_s {
	int fd;
	tapcfg_t *tapcfg;
	unsigned int netmask;
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

	printf("Starting reader thread\n");

	do {
		fd_set rfds;
		struct timeval tv;

		struct sockaddr_in6 saddr;
		socklen_t socklen;

		FD_ZERO(&rfds);
		FD_SET(data->fd, &rfds);

		tv.tv_sec = tunnel->waitms / 1000;
		tv.tv_usec = (tunnel->waitms % 1000) * 1000;
		ret = select(data->fd+1, &rfds, NULL, NULL, &tv);
		if (ret == -1) {
			printf("Error when selecting for fd: %s (%d)\n",
			       strerror(GetLastError()), GetLastError());
			break;
		}

		if (!FD_ISSET(data->fd, &rfds))
			goto read_loop;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_addr = in6addr_any;

		socklen = sizeof(saddr);
		ret = recvfrom(data->fd, (char *) (buf+14), sizeof(buf)-14, 0,
			       (struct sockaddr *) &saddr, &socklen);
		if (ret == -1) {
			printf("Error reading packet: %s (%d)\n",
			       strerror(GetLastError()), GetLastError());
			break;
		} else if (ret == 0) {
			printf("Disconnected from the server\n");
			break;
		} else {
#ifdef DEBUG
			printf("Read packet of size %d from %d.%d.%d.%d\n",
			       ret, buf[26], buf[27], buf[28], buf[29]);
#endif
		}

		if (memcmp(&saddr.sin6_addr,
		           &tunnel->endpoint.remote_ipv6,
		           sizeof(saddr.sin6_addr))) {
			printf("Discarding packet from incorrect host\n");
			goto read_loop;
		}

		ret = tapcfg_write(data->tapcfg, buf, ret+14);
		if (ret == -1) {
			printf("Error writing packet\n");
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

	printf("Finished reader thread\n");

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

	printf("Starting writer thread\n");

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
				printf("ARP request packet invalid\n");
				goto write_loop;
			}

			if (memcmp(buf+6, localhw, 6)) {
				printf("ARP coming from unknown device\n");
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
				printf("Target IP of ARP not available\n");
				goto write_loop;
			}

			memcpy(buf+32, buf+22, 10);
			memcpy(buf+22, routerhw, 6);
			memcpy(buf+28, &ipaddr, 4);

			/* Change opcode type into reply */
			buf[21] = 0x02;

			printf("Replied to an ARP request\n");
			tapcfg_write(data->tapcfg, buf, buflen);
		} else if (type == 0x800) {
			const char broadcasthw[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

			if (!memcmp(buf, routerhw, 6) ||
			    !memcmp(buf, broadcasthw, 6)) {
				fd_set wfds;
				struct sockaddr_in6 saddr;
				int ret;

				memset(&saddr, 0, sizeof(saddr));
				saddr.sin6_family = AF_INET6;
				saddr.sin6_addr = tunnel->endpoint.remote_ipv6;

				FD_ZERO(&wfds);
				FD_SET(data->fd, &wfds);
				ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
				if (ret == -1) {
					printf("Error when selecting for fd: %s (%d)\n",
					       strerror(GetLastError()), GetLastError());
					break;
				}

				ret = sendto(data->fd, (char *) (buf+14), buflen-14, 0,
				             (struct sockaddr *) &saddr,
				             sizeof(saddr));
				if (ret <= 0) {
					printf("Error writing to socket: %s (%d)\n",
					       strerror(GetLastError()), GetLastError());
					break;
				}

#ifdef DEBUG
				printf("Wrote %d bytes to the server\n");
#endif
			} else {
#ifdef DEBUG
				printf("Found an IPv4 packet to other host %d.%d.%d.%d\n",
				       buf[30], buf[31], buf[32], buf[33]);
#endif
			}
		} else {
			printf("Packet of unhandled protocol type 0x%04x\n", type);
		}

write_loop:
		MUTEX_LOCK(tunnel->run_mutex);
		running = tunnel->running;
		MUTEX_UNLOCK(tunnel->run_mutex);
	} while (running);

	MUTEX_LOCK(tunnel->run_mutex);
	tunnel->running = 0;
	MUTEX_UNLOCK(tunnel->run_mutex);

	printf("Finished writer thread\n");

	return 0;
}

static int
init(tunnel_t *tunnel)
{
	const endpoint_t *endpoint;
	int local_mtu;
	int sock;
	tapcfg_t *tapcfg;
	char address[INET_ADDRSTRLEN];
	unsigned int netmask;
	tunnel_data_t *data;
	int i;

	assert(tunnel);
	endpoint = &tunnel->endpoint;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_IPIP);
	assert(sock >= 0);

	assert(inet_ntop(AF_INET, &endpoint->local_ipv4,
	                 address, sizeof(address)));

	tapcfg = tapcfg_init();
	assert(tapcfg_start(tapcfg, "ipv4tun", 1) >= 0);
	assert(tapcfg_iface_set_ipv4(tapcfg, address,
	                             endpoint->local_prefix) >= 0);

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
			return 0;
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
		return 0;
	}
	data->fd = sock;
	data->tapcfg = tapcfg;
	data->netmask = htonl(netmask);
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
v4v6_initmod()
{
	return &module;
}

