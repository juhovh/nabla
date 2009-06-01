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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "compat.h"
#include "tunnel.h"
#include "login_tic.h"

int running;

static void
sigterm(int i)
{
	running = 0;
	signal(i, SIG_IGN);
}


int
main(int argc, char *argv[])
{
	endpoint_t endpoint;
	tunnel_t *tunnel;
	int ret;

	INIT_SOCKETLIB(ret);

	signal(SIGTERM, &sigterm);
	signal(SIGINT, &sigterm);

	memset(&endpoint, 0, sizeof(endpoint));
	if (argc < 2) {
		printf("Not enough arguments\n");
		return 1;
	}

	if (!strcmp(argv[1], "ether") && argc == 4) {
		endpoint.type = TUNNEL_TYPE_ETHER;
		inet_pton(AF_INET, argv[2], &endpoint.remote_ipv4);
		endpoint.remote_port = atoi(argv[3]);
	} else if (!strcmp(argv[1], "tic")) {
		if (argc == 4) {
			ticinfo_t *ticinfo = tic_init(argv[2], argv[3],
			                              "tic.sixxs.net", NULL);
			assert(tic_fill_endpoint(ticinfo, &endpoint) >= 0);
			tic_destroy(ticinfo);
		} else {
			endpoint.type = TUNNEL_TYPE_AYIYA;
			inet_pton(AF_INET, "127.0.0.1", &endpoint.remote_ipv4);
			endpoint.remote_port = 1234;
			endpoint.local_ipv6 = in6addr_loopback;
			endpoint.remote_ipv6 = in6addr_loopback;
			endpoint.local_ipv6.s6_addr[0] = 0x20;
			endpoint.local_ipv6.s6_addr[1] = 0x01;
			endpoint.local_prefix = 64;
		}
	} else if (!strcmp(argv[1], "v4v6")) {
		endpoint.type = TUNNEL_TYPE_V4V6;
		inet_pton(AF_INET, "10.0.1.2", &endpoint.local_ipv4);
		endpoint.remote_ipv6 = in6addr_loopback;
		endpoint.local_prefix = 30;
	} else if (!strcmp(argv[1], "v4v6test")) {
		endpoint.type = TUNNEL_TYPE_V4V6;
		inet_pton(AF_INET6, "2001::2", &endpoint.remote_ipv6);
		inet_pton(AF_INET, "10.0.0.1", &endpoint.local_ipv4);
		endpoint.local_prefix = 24;
	} else if (!strcmp(argv[1], "v6v4test")) {
		endpoint.type = TUNNEL_TYPE_V6V4;
		inet_pton(AF_INET6, "2001::1", &endpoint.local_ipv6);
		inet_pton(AF_INET, "127.0.0.1", &endpoint.remote_ipv4);
		endpoint.local_prefix = 64;
	} else {
		printf("Incorrect tunnel information\n");
		return 1;
	}

	tunnel = tunnel_init(&endpoint);
	if (!tunnel) {
		printf("Error initializing the tunnel, check permissions\n");
		return -1;
	}

	if (tunnel_start(tunnel) == -1) {
		printf("Error starting the tunnel\n");
		return -1;
	}

	running = 1;
	while (running && tunnel_running(tunnel)) {
		sleepms(1000);
	}

	tunnel_destroy(tunnel);

	CLOSE_SOCKETLIB(ret);

	return 0;
}
