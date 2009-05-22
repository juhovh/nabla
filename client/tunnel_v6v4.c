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
 *   remote_ipv4   - IPv4 address of the server
 *   local_ipv6    - Local IPv6 address of the tunnel
 *   remote_ipv6   - Remote IPv6 address of the tunnel
 *   local_prefix  - Prefix of the local IPv6 address
 *   password      - (optional) Shared password from the server (for beats)
 *   beat_interval - (optional) Interval of beat (in seconds)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "compat.h"
#include "tapcfg.h"
#include "tunnel.h"
#include "command.h"

#include "hash_md5.h"

#define HEARTBEAT_PORT 3740

struct tunnel_data_s {
	int fd;
	tapcfg_t *tapcfg;
};

static const char routerhw[] = { 0x00, 0x01, 0x23, 0x45, 0x67, 0x89 };

static THREAD_RETVAL
reader_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	tunnel_data_t *data;
	unsigned char buf[4096];
	char allhosts[] = { 0x33, 0x33, 0xff, 0x00, 0x00, 0x02 };
	int running;
	int ret;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	memcpy(buf, allhosts, 6);
	memcpy(buf+6, routerhw, 6);
	buf[12] = 0x86;
	buf[13] = 0xdd;

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

		logger_log(tunnel->logger, LOG_DEBUG,
		           "Trying to read data from server\n");

		socklen = sizeof(saddr);
		ret = recvfrom(data->fd, (char *) (buf+14), sizeof(buf)-14, 0,
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

		if (saddr.sin_addr.s_addr != tunnel->endpoint.remote_ipv4.s_addr) {
			logger_log(tunnel->logger, LOG_NOTICE,
			           "Discarding packet from incorrect host\n");
			goto read_loop;
		}

		logger_log(tunnel->logger, LOG_DEBUG,
		           "Read %d bytes from the server\n", ret);

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

		/* Ignore router solicitation packets as useless */
		if (buf[14+6] == 58 && buf[14+7] == 255 && buf[14+40] == 133) {
			goto write_loop;
		}

		/* Check for neighbour discovery packets (ICMPv6, ND_SOL, hop=255)
		 * (XXX: doesn't check for a chain, but ND is usually without)
		 */
		if (buf[14+6] == 58 && buf[14+7] == 255 && buf[14+40] == 135) {
			unsigned char ipbuf[16];
			int length, checksum;
			int i;

			/* Ignore unspecified ND's as they are used for DAD */
			memset(&ipbuf, 0, sizeof(ipbuf));
			if (!memcmp(buf+14+8, ipbuf, sizeof(ipbuf))) {
				logger_log(tunnel->logger, LOG_DEBUG,
				           "Found ND DAD request that is ignored\n");
				goto write_loop;
			}

			/* Neighbor advert is ICMPv6 header, IPv6 address and
			 * 8 bytes of target link-layer address option */
			length = 8+16+8;

			/* Set Ethernet src/dst */
			memcpy(buf, buf+6, 6);
			memcpy(buf+6, routerhw, 6);

			/* Add packet content length */
			buf[14+4] = length >> 8;
			buf[14+5] = length;

			/* Set IPv6 src/dst */
			memcpy(buf+14+24, buf+14+8, 16);        /* Destination address (from source) */
			memcpy(buf+14+8, buf+14+40+8, 16);	/* Source address (from ICMPv6 packet) */

			/* Set ICMPv6 type and code */
			buf[14+40] = 136;
			buf[14+40+1] = 0;

			/* Add target link-layer address option*/
			buf[14+40+8+16] = 2;
			buf[14+40+8+16+1] = 1;
			memcpy(buf+14+40+8+16+2, routerhw, 6);

			/* Zero checksum */
			checksum = 0;
			buf[14+40+2] = 0;
			buf[14+40+3] = 0;

			/* Add pseudo-header into the checksum */
			checksum += buf[14+4] << 8 | buf[14+5];
			checksum += buf[14+6];
			for (i=0; i<32; i++)
				checksum += buf[14+8+i] << ((i%2 == 0)?8:0);

			/* Checksum the actual data */
			for (i=0; i<length; i++)
				checksum += buf[14+40+i] << ((i%2 == 0)?8:0);

			/* Store the final checksum into ICMPv6 packet */
			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;
			buf[14+40+2] = checksum >> 8;
			buf[14+40+3] = checksum;

			logger_log(tunnel->logger, LOG_INFO,
			           "Writing reply to ND request\n");

			ret = tapcfg_write(data->tapcfg, buf, 14+40+length);
			if (ret == -1) {
				logger_log(tunnel->logger, LOG_ERR,
				           "Error writing packet\n");
				break;
			}
			goto write_loop;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr = tunnel->endpoint.remote_ipv4;

		FD_ZERO(&wfds);
		FD_SET(data->fd, &wfds);
		ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error when selecting for fd: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		}

		ret = sendto(data->fd, (char *) (buf+14), len-14, 0,
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
	int local_mtu;
	int sock;
	tapcfg_t *tapcfg;
	tunnel_data_t *data;
	int ret;

	assert(tunnel);
	endpoint = &tunnel->endpoint;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IPV6);
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

	local_mtu = 1280;
	if (tapcfg_iface_set_mtu(tapcfg, local_mtu) < 0) {
		/* Error setting MTU not fatal if current MTU small enough */
		if (tapcfg_iface_get_mtu(tapcfg) > local_mtu) {
			closesocket(sock);
			tapcfg_destroy(tapcfg);
			return -1;
		}
	}

	data = calloc(1, sizeof(tunnel_data_t));
	if (!data) {
		closesocket(sock);
		tapcfg_destroy(tapcfg);
		return -1;
	}
	data->fd = sock;
	data->tapcfg = tapcfg;
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
	char *ifname;

	assert(tunnel);
	assert(tunnel->privdata);

	tapcfg = tunnel->privdata->tapcfg;
	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_IPV6_UP);

	ifname = tapcfg_get_ifname(tapcfg);
	assert(command_add_ipv6(ifname, &tunnel->endpoint.local_ipv6, tunnel->endpoint.local_prefix) >= -1);
	free(ifname);
	
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

static int
beat(tunnel_t *tunnel)
{
	assert(tunnel);
	assert(tunnel->privdata);

	if (tunnel->endpoint.type == TUNNEL_TYPE_HEARTBEAT) {
		fd_set wfds;
		struct MD5Context md5;
		unsigned char digest[16];
		char buf[1024], *tmpstr;
		time_t current_time;
		struct sockaddr_in saddr;
		char ipv6str[INET6_ADDRSTRLEN];
		int sock;
		int i, ret;

		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (!sock) {
			return -1;
		}

		assert(inet_ntop(AF_INET6, &tunnel->endpoint.local_ipv6,
		                 ipv6str, sizeof(ipv6str)));
		current_time = time(NULL);

		/* Create the string to send including our password */
		snprintf(buf, sizeof(buf), "HEARTBEAT TUNNEL %s %s %ld %s",
			 ipv6str, "sender", (long int) current_time,
		         tunnel->endpoint.password);

		/* Generate a MD5 */
		MD5Init(&md5);
		MD5Update(&md5, (unsigned char *) buf, strlen(buf));
		MD5Final(digest, &md5);

		tmpstr = buf;
		tmpstr += snprintf(buf, sizeof(buf)-17, "HEARTBEAT TUNNEL %s %s %ld ",
				   ipv6str, "sender", (long int) current_time);

		for (i = 0; i < 16; i++) {
			sprintf(tmpstr, "%02x", digest[i]);
			tmpstr += 2;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr = tunnel->endpoint.remote_ipv4;
		saddr.sin_port = htons(HEARTBEAT_PORT);

		FD_ZERO(&wfds);
		FD_SET(sock, &wfds);
		ret = select(sock+1, NULL, &wfds, NULL, NULL);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error when selecting for fd: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			return -1;
		}

		ret = sendto(sock, buf, strlen(buf), 0,
			     (struct sockaddr *) &saddr, sizeof(saddr));
		if (ret < -1) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error sending heartbeat: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			return -1;
		}

		closesocket(sock);
	}

	return 0;
}

static tunnel_mod_t module =
{
	init,
	start,
	stop,
	beat,
	destroy
};

const tunnel_mod_t *
v6v4_initmod()
{
	return &module;
}

