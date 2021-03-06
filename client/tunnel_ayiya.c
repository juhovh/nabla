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

/* This file is heavily based on ayiya.c from AICCU utility
 * written by Jeroen Massar and released under 3 clause BSD
 * Copyright 2003-2005 SixXS - http://www.sixxs.net
 * http://www.sixxs.net/tools/aiccu/LICENSE
 */

/* Uses the following variables from endpoint_t struct:
 *   local_ipv6    - Local IPv6 address of the tunnel
 *   local_prefix  - Prefix of the local IPv6 address
 *   remote_ipv6   - Remote IPv6 address of the tunnel
 *   remote_ipv4   - IPv4 address of the AYIYA server
 *   remote_port   - (optional) UDP port of the server
 *   password      - Shared password from the server
 *   beat_interval - (optional) interval of beat (in seconds)
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "compat.h"
#include "tapcfg.h"
#include "tunnel.h"
#include "command.h"

#include "ayiya.h"
#include "hash_sha1.h"

/* This is only for tic_checktime */
#include "tic/tic.h"

struct pseudo_ayh {
	struct ayiyahdr	ayh;
	struct in6_addr	identity;
	sha1_byte	hash[SHA1_DIGEST_LENGTH];
	char		payload[2048];
};

struct tunnel_data_s {
	int fd;
	tapcfg_t *tapcfg;
	sha1_byte ayiya_hash[SHA1_DIGEST_LENGTH];
};

static const char routerhw[] = { 0x00, 0x01, 0x23, 0x45, 0x67, 0x89 };

static THREAD_RETVAL
reader_thread(void *arg)
{
	tunnel_t *tunnel = arg;
	tunnel_data_t *data;
	unsigned char buf[4096];
	const unsigned char *hwaddr;

	struct pseudo_ayh *s = (struct pseudo_ayh *) (buf+14);
	SHA_CTX sha1;
	sha1_byte their_hash[SHA1_DIGEST_LENGTH];
	sha1_byte our_hash[SHA1_DIGEST_LENGTH];

	int running;
	int ret;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	hwaddr = (const unsigned char *)
		tapcfg_iface_get_hwaddr(data->tapcfg, NULL);

	logger_log(tunnel->logger, LOG_INFO,
	           "Hwaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	           hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
	           hwaddr[4], hwaddr[5]);

	memcpy(buf, hwaddr, 6);
	memcpy(buf+6, routerhw, 6);
	buf[12] = 0x86;
	buf[13] = 0xdd;

	logger_log(tunnel->logger, LOG_INFO, "Starting reader thread\n");

	do {
		fd_set rfds;
		struct timeval tv;

		struct sockaddr_in saddr;
		socklen_t socklen;
		int i, buflen;

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

		if (saddr.sin_addr.s_addr != tunnel->endpoint.remote_ipv4.s_addr ||
		    ntohs(saddr.sin_port) != tunnel->endpoint.remote_port) {
			logger_log(tunnel->logger, LOG_NOTICE,
			           "Discarding packet from incorrect host\n");
			goto read_loop;
		}

		logger_log(tunnel->logger, LOG_DEBUG,
		           "Read %d bytes from the server\n", ret);

		if (ret < sizeof(struct ayiyahdr)) {
			logger_log(tunnel->logger, LOG_ERR, "Received packet is too short");
			break;
		}

		if (s->ayh.ayh_idlen != 4 ||
		    s->ayh.ayh_idtype != ayiya_id_integer ||
		    s->ayh.ayh_siglen != 5 ||
		    s->ayh.ayh_hshmeth != ayiya_hash_sha1 ||
		    s->ayh.ayh_autmeth != ayiya_auth_sharedsecret ||
		    (s->ayh.ayh_nextheader != IPPROTO_IPV6 &&
		     s->ayh.ayh_nextheader != IPPROTO_NONE) ||
		    (s->ayh.ayh_opcode != ayiya_op_forward &&
		     s->ayh.ayh_opcode != ayiya_op_echo_request &&
		     s->ayh.ayh_opcode != ayiya_op_echo_request_forward))
		{
			/* Invalid AYIYA packet */
			logger_log(tunnel->logger, LOG_WARNING, "Dropping invalid AYIYA packet\n");
			logger_log(tunnel->logger, LOG_WARNING, "idlen:   %u != %u\n", s->ayh.ayh_idlen, 4);
			logger_log(tunnel->logger, LOG_WARNING, "idtype:  %u != %u\n", s->ayh.ayh_idtype, ayiya_id_integer);
			logger_log(tunnel->logger, LOG_WARNING, "siglen:  %u != %u\n", s->ayh.ayh_siglen, 5);
			logger_log(tunnel->logger, LOG_WARNING, "hshmeth: %u != %u\n", s->ayh.ayh_hshmeth, ayiya_hash_sha1);
			logger_log(tunnel->logger, LOG_WARNING, "autmeth: %u != %u\n", s->ayh.ayh_autmeth, ayiya_auth_sharedsecret);
			logger_log(tunnel->logger, LOG_WARNING, "nexth  : %u != %u || %u\n", s->ayh.ayh_nextheader, IPPROTO_IPV6, IPPROTO_NONE);
			logger_log(tunnel->logger, LOG_WARNING, "opcode : %u != %u || %u || %u\n", s->ayh.ayh_opcode, ayiya_op_forward, ayiya_op_echo_request, ayiya_op_echo_request_forward);
			goto read_loop;
		}

		if (memcmp(&s->identity, &tunnel->endpoint.remote_ipv6, sizeof(s->identity)) != 0) {
			char strbuf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &s->identity, strbuf, sizeof(strbuf));
			logger_log(tunnel->logger, LOG_WARNING,
			           "Received packet from a wrong identity \"%s\"\n", strbuf);
			goto read_loop;
		}

		/* Verify the epochtime */
		i = tic_checktime(ntohl(s->ayh.ayh_epochtime));
		if (i != 0) {
			char strbuf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &s->identity, strbuf, sizeof(strbuf));
			logger_log(tunnel->logger, LOG_WARNING,
			           "Time is %d seconds off for %s\n", i, buf);
			goto read_loop;
		}

		/* Save their hash */
		memcpy(&their_hash, &s->hash, sizeof(their_hash));

		/* Copy in our SHA1 hash */
		memcpy(&s->hash, &data->ayiya_hash, sizeof(s->hash));

		/* Generate a SHA1 of the header + identity + shared secret */
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, (sha1_byte *) s, ret);
		SHA1_Final(our_hash, &sha1);

		/* Compare the SHA1's */
		if (memcmp(&their_hash, &our_hash, sizeof(their_hash)) != 0) {
			logger_log(tunnel->logger, LOG_WARNING, "Incorrect Hash received\n");
			goto read_loop;
		}

		if (s->ayh.ayh_nextheader == IPPROTO_IPV6) {
			/* Verify that this is really IPv6 */
			if (s->payload[0] >> 4 != 6) {
				logger_log(tunnel->logger, LOG_WARNING,
				           "Received packet didn't start with a 6, thus is not IPv6\n");
				goto read_loop;
			}
		}

		buflen = ret + sizeof(s->payload) - sizeof(*s);
		memmove(buf+14, s->payload, buflen);

		ret = tapcfg_write(data->tapcfg, buf, buflen+14);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_ERR, "Error writing packet\n");
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

	struct pseudo_ayh s;
	SHA_CTX sha1;
	sha1_byte hash[SHA1_DIGEST_LENGTH];

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

			logger_log(tunnel->logger, LOG_DEBUG,
			           "Writing reply to ND request\n");
			ret = tapcfg_write(data->tapcfg, buf, 14+40+length);
			if (ret == -1) {
				logger_log(tunnel->logger, LOG_ERR, "Error writing packet\n");
				break;
			}
			goto write_loop;
		}
		/* Prefill some standard AYIYA values */
		memset(&s, 0, sizeof(s));
		s.ayh.ayh_idlen          = 4;                       /* 2^4 = 16 bytes = 128 bits (IPv6 address) */
		s.ayh.ayh_idtype         = ayiya_id_integer;
		s.ayh.ayh_siglen         = 5;                       /* 5*4 = 20 bytes = 160 bits (SHA1) */
		s.ayh.ayh_hshmeth        = ayiya_hash_sha1;
		s.ayh.ayh_autmeth        = ayiya_auth_sharedsecret;
		s.ayh.ayh_opcode         = ayiya_op_forward;
		s.ayh.ayh_nextheader     = IPPROTO_IPV6;

		/* Our IPv6 side of this tunnel */
		memcpy(&s.identity, &tunnel->endpoint.local_ipv6, sizeof(s.identity));

		/* The payload (XXX: should we check the size) */
		memcpy(s.payload, buf+14, len-14);

		/* Fill in the current time */
		s.ayh.ayh_epochtime = htonl((unsigned long) time(NULL));

		/*
		 * The hash of the shared secret needs to be in the
		 * spot where we later put the complete hash
		 */
		memcpy(s.hash, data->ayiya_hash, sizeof(s.hash));

		/* Update the length to include AYIYA header */
		len = sizeof(s) - sizeof(s.payload) + (len-14);

		/* Generate a SHA1 of the complete AYIYA packet*/
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, (sha1_byte *) &s, len);
		SHA1_Final(hash, &sha1);

		/* Store the hash in the actual packet */
		memcpy(s.hash, hash, sizeof(s.hash));

		/* Send it onto the network */
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr = tunnel->endpoint.remote_ipv4;
		saddr.sin_port = htons(tunnel->endpoint.remote_port);

		FD_ZERO(&wfds);
		FD_SET(data->fd, &wfds);
		ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
		if (ret == -1) {
			logger_log(tunnel->logger, LOG_INFO,
			           "Error when selecting for fd: %s (%d)\n",
			           strerror(GetLastError()), GetLastError());
			break;
		}

		ret = sendto(data->fd, (const char *) &s, len, 0,
		             (struct sockaddr *) &saddr,
		             sizeof(saddr));
		if (ret <= 0) {
			logger_log(tunnel->logger, LOG_ERR,
			           "Error writing to socket: %s (%d)\n",
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
	SHA_CTX sha1;
	int ret;

	assert(tunnel);
	endpoint = &tunnel->endpoint;

	if (!endpoint->remote_port) {
		/* As a special case, override the constness */
		((endpoint_t *) endpoint)->remote_port = AYIYA_PORT;
	}

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

	local_mtu = 1280;
	if (tapcfg_iface_set_mtu(tapcfg, local_mtu) < 0) {
		/* Error setting MTU not fatal if current MTU small enough */
		if (tapcfg_iface_get_mtu(tapcfg) > local_mtu) {
			logger_log(tunnel->logger, LOG_ERR, "Could not set MTU as small enough\n");
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

	/* Calculate shared secret from the password */
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, (const sha1_byte *) endpoint->password,
	            strlen(endpoint->password));
	SHA1_Final(data->ayiya_hash, &sha1);

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
	assert(command_add_ipv6(ifname, &tunnel->endpoint.local_ipv6, tunnel->endpoint.local_prefix) >= 0);
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
	tunnel_data_t *data;
	fd_set wfds;
	int ret;

	SHA_CTX	                sha1;
	sha1_byte               hash[SHA1_DIGEST_LENGTH];
	struct sockaddr_in      target;
	struct pseudo_ayh       s;
	int                     lenout, n;

	assert(tunnel);
	assert(tunnel->privdata);
	data = tunnel->privdata;

	/* We tunnel over IPv4 */
	memset(&target, 0, sizeof(target));
	target.sin_family       = AF_INET;
	memcpy(&target.sin_addr, &tunnel->endpoint.remote_ipv4, sizeof(target.sin_addr));
	target.sin_port	        = htons(tunnel->endpoint.remote_port);

	/* Prefill some standard AYIYA values */
	memset(&s, 0, sizeof(s));
	s.ayh.ayh_idlen	        = 4;                    /* 2^4 = 16 bytes = 128 bits (IPv6 address) */
	s.ayh.ayh_idtype        = ayiya_id_integer;
	s.ayh.ayh_siglen        = 5;                    /* 5*4 = 20 bytes = 160 bits (SHA1) */
	s.ayh.ayh_hshmeth       = ayiya_hash_sha1;
	s.ayh.ayh_autmeth       = ayiya_auth_sharedsecret;
	s.ayh.ayh_opcode        = ayiya_op_noop;
	s.ayh.ayh_nextheader    = IPPROTO_NONE;

	/* Our IPv6 side of this tunnel */
	memcpy(&s.identity, &tunnel->endpoint.local_ipv6, sizeof(s.identity));

	/* No Payload */

	/* Fill in the current time */
	s.ayh.ayh_epochtime = htonl((unsigned long) time(NULL));

	/* Our IPv6 side of this tunnel */
	memcpy(&s.identity, &tunnel->endpoint.local_ipv6, sizeof(s.identity));

	/*
	 * The hash of the shared secret needs to be in the
	 * spot where we later put the complete hash
	 */
	memcpy(&s.hash, data->ayiya_hash, sizeof(s.hash));

	/* Generate a SHA1 of the complete AYIYA packet*/
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, (sha1_byte *) &s, sizeof(s) - sizeof(s.payload));
	SHA1_Final(hash, &sha1);

	/* Store the hash in the actual packet */
	memcpy(&s.hash, &hash, sizeof(s.hash));

	FD_ZERO(&wfds);
	FD_SET(data->fd, &wfds);
	ret = select(data->fd+1, NULL, &wfds, NULL, NULL);
	if (ret == -1) {
		logger_log(tunnel->logger, LOG_ERR,
		           "Error when selecting for fd: %s (%d)\n",
		           strerror(GetLastError()), GetLastError());
		return -1;
	}

	/* Send it onto the network */
	n = sizeof(s)-sizeof(s.payload);
	lenout = sendto(data->fd,
	                (const char *) &s, (unsigned int) n, 0,
	                (struct sockaddr *) &target, sizeof(target));

	if (lenout < 0) {
		logger_log(tunnel->logger, LOG_ERR,
		           "Error (%d) while sending %u bytes sent to network: %s (%d)\n",
		           lenout, n, strerror(GetLastError()), GetLastError());
		return -1;
	} else if (n != lenout) {
		logger_log(tunnel->logger, LOG_ERR,
		           "Only %u of %u bytes sent to network: %s (%d)\n",
		           lenout, n, strerror(errno), errno);
		return -1;
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
ayiya_initmod()
{
	return &module;
}

