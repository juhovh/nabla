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

/* This file is heavily based on main.c from AICCU utility
 * written by Jeroen Massar and released under 3 clause BSD
 * Copyright 2003-2005 SixXS - http://www.sixxs.net
 * http://www.sixxs.net/tools/aiccu/LICENSE
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "tunnel.h"
#include "tic/tic.h"

struct ticinfo_s {
	struct TIC_Tunnel *tunnel;
};
typedef struct ticinfo_s ticinfo_t;


ticinfo_t *
tic_init(const char *username,
         const char *password,
         const char *server,
         const char *tunnel_id)
{
	struct TIC_conf tic;
	struct TIC_sTunnel *hsTunnel, *t;
	struct TIC_Tunnel *hTunnel;
	ticinfo_t *ticinfo;
	char *tunid = NULL;

	/* Login to the TIC Server */
	if (!tic_Login(&tic, username, password, server))
		return NULL;

	/*
	 * Don't try to list the tunnels when
	 * we already have a tunnel_id configured
	 */
	if (tunnel_id) 
		tunid = strdup(tunnel_id);

	if (!tunid) {
		hsTunnel = tic_ListTunnels(&tic);
		if (!hsTunnel) {
			printf("No tunnel available, request one first\n");
			tic_Free_sTunnel(hsTunnel);
			tic_Logout(&tic, "I didn't have any tunnels to select");
			return NULL;
		}

		if (hsTunnel->next) {
			printf("Multiple tunnels available, please pick one from the following list and configure the aiccu.conf using it\n");
			for (t = hsTunnel; t; t = t->next) {
				printf("%s %s %s %s\n", t->sId, t->sIPv6, t->sIPv4, t->sPOPId);
			}
			tic_Free_sTunnel(hsTunnel);
			tic_Logout(&tic, "User still needed to select a tunnel");
			return NULL;
		}
		tunid = strdup(hsTunnel->sId);

		/* Free the info */
		tic_Free_sTunnel(hsTunnel);
	}

	/* Get Tunnel Information */
	hTunnel = tic_GetTunnel(&tic, tunid);
	free(tunid);
	if (!hTunnel) {
		tic_Logout(&tic, "No such tunnel");
		return NULL;
	}

	/* Logout, TIC is not needed any more */
	tic_Logout(&tic, NULL);

	/* Swee.... sufficient information */
	ticinfo = calloc(1, sizeof(ticinfo_t));
	if (!ticinfo)
		return NULL;

	ticinfo->tunnel = hTunnel;

	return ticinfo;
}

int
tic_fill_endpoint(ticinfo_t *ticinfo, endpoint_t *endpoint)
{
	struct TIC_Tunnel *tunnel;

	assert(ticinfo);
	assert(endpoint);
	tunnel = ticinfo->tunnel;

	if (!strcmp(tunnel->sType, "ayiya")) {
		endpoint->type = TUNNEL_TYPE_AYIYA;
		assert(inet_pton(AF_INET6, tunnel->sIPv6_Local, &endpoint->local_ipv6) > 0);
		assert(inet_pton(AF_INET6, tunnel->sIPv6_POP, &endpoint->remote_ipv6) > 0);
		assert((endpoint->local_prefix = tunnel->nIPv6_PrefixLength) >= 0);
		assert((endpoint->local_mtu = tunnel->nMTU) >= 0);
		assert(inet_pton(AF_INET, tunnel->sIPv4_POP, &endpoint->remote_ipv4) > 0);
		assert(strncpy(endpoint->password, tunnel->sPassword, sizeof(endpoint->password)));
		assert((endpoint->beat_interval = tunnel->nHeartbeat_Interval) >= 0);
	} else if (!strcmp(tunnel->sType, "6in4-heartbeat")) {
		endpoint->type = TUNNEL_TYPE_HEARTBEAT;
		assert(inet_pton(AF_INET6, tunnel->sIPv6_Local, &endpoint->local_ipv6) > 0);
		assert(inet_pton(AF_INET6, tunnel->sIPv6_POP, &endpoint->remote_ipv6) > 0);
		assert((endpoint->local_prefix = tunnel->nIPv6_PrefixLength) >= 0);
		assert((endpoint->local_mtu = tunnel->nMTU) >= 0);
		assert(inet_pton(AF_INET, tunnel->sIPv4_POP, &endpoint->remote_ipv4) > 0);
		assert(strncpy(endpoint->password, tunnel->sPassword, sizeof(endpoint->password)));
		assert((endpoint->beat_interval = tunnel->nHeartbeat_Interval) >= 0);
	} else if (!strcmp(tunnel->sType, "6in4")) {
		endpoint->type = TUNNEL_TYPE_V6V4;
		assert(inet_pton(AF_INET6, tunnel->sIPv6_Local, &endpoint->local_ipv6) > 0);
		assert(inet_pton(AF_INET6, tunnel->sIPv6_POP, &endpoint->remote_ipv6) > 0);
		assert((endpoint->local_prefix = tunnel->nIPv6_PrefixLength) >= 0);
		assert((endpoint->local_mtu = tunnel->nMTU) >= 0);
		assert(inet_pton(AF_INET, tunnel->sIPv4_POP, &endpoint->remote_ipv4) > 0);
	} else {
		return -1;
	}

	return 0;
}

void
tic_destroy(ticinfo_t *ticinfo)
{
	if (ticinfo) {
		tic_Free_Tunnel(ticinfo->tunnel);
		free(ticinfo);
	}
}
