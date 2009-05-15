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

#ifndef TUNNEL_H
#define TUNNEL_H

#include "compat.h"
#include "threads.h"

enum tunnel_type_e {
	TUNNEL_TYPE_V4V6,
	TUNNEL_TYPE_ETHER,
	TUNNEL_TYPE_AYIYA,
	TUNNEL_TYPE_V6V4,
	TUNNEL_TYPE_HEARTBEAT
};
typedef enum tunnel_type_e tunnel_type_t;

struct endpoint_s {
	tunnel_type_t type;

	struct in_addr local_ipv4;
	struct in6_addr local_ipv6;
	int local_prefix;
	int local_mtu;

	struct in_addr remote_ipv4;
	struct in6_addr remote_ipv6;
	int remote_port;

	char password[256];
	int beat_interval;
};
typedef struct endpoint_s endpoint_t;

typedef struct tunnel_mod_s tunnel_mod_t;
typedef struct tunnel_data_s tunnel_data_t;

struct tunnel_s {
	const tunnel_mod_t *tunmod;
	int waitms;

	int running;
	int joined;

	mutex_handle_t run_mutex;
	mutex_handle_t join_mutex;

	thread_handle_t reader;
	thread_handle_t writer;
	thread_handle_t beater;

	const endpoint_t endpoint;
	tunnel_data_t *privdata;
};
typedef struct tunnel_s tunnel_t;

struct tunnel_mod_s {
	int (*init)(tunnel_t *tunnel);
	int (*start)(tunnel_t *tunnel);
	int (*stop)(tunnel_t *tunnel);
	int (*beat)(tunnel_t *tunnel);
	void (*destroy)(tunnel_t *tunnel);
};

tunnel_t *tunnel_init(endpoint_t *endpoint);
int tunnel_start(tunnel_t *tunnel);
int tunnel_stop(tunnel_t *tunnel);
int tunnel_running(tunnel_t *tunnel);
void tunnel_destroy(tunnel_t *tunnel);


const tunnel_mod_t *v4v6_initmod();
const tunnel_mod_t *ether_initmod();
const tunnel_mod_t *ayiya_initmod();
const tunnel_mod_t *v6v4_initmod();

#endif /* TUNNEL_H */
