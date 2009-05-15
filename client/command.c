/* NABLA - Automatic IP Tunneling and Connectivity
 * Copyright (C) 2009  Juho Vähä-Herttua
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "compat.h"

int
command_add_ipv6(const char *ifname,
                 const struct in6_addr *addr, unsigned int prefix)
{
	char addrstr[INET6_ADDRSTRLEN];
	char cmdstr[512];
	int ret;

	assert(ifname);
	assert(addr);
	assert(prefix <= 128);

	cmdstr[sizeof(cmdstr)-1] = '\0';

	assert(inet_ntop(AF_INET6, addr, addrstr, sizeof(addrstr)));

#if defined(_WIN32) || defined(_WIN64)
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "netsh interface ipv6 set address \"%s\" %s\n", ifname, addrstr);
#ifdef DEBUG
	printf("Calling external program: %s\n", cmdstr);
#endif
	if (system(cmdstr)) {
		printf("First call to system failed\n");
		return -1;
	}

	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "netsh interface ipv6 add route %s/%d \"%s\"\n", addrstr, prefix, ifname);
#elif defined(__linux__)
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "ip -6 addr add %s/%u dev %s\n", addrstr, prefix, ifname);
#elif defined(__sun__)
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "ifconfig ip.%s inet6 addif %s/%d up\n", ifname, addrstr, prefix);
#else
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "ifconfig %s inet6 %s prefixlen %d alias\n", ifname, addrstr, prefix);
#endif
	
#ifdef DEBUG
	printf("Calling external program: %s", cmdstr);
#endif
	ret = system(cmdstr);
	if (ret) {
		printf("Calling external program failed\n");
		return -1;
	}

	return ret;
}


int
command_set_route6(const char *ifname,
                   const struct in6_addr *addr)
{
	char addrstr[INET6_ADDRSTRLEN];
	char cmdstr[512];
	int ret;

	assert(ifname);
	assert(addr);

	cmdstr[sizeof(cmdstr)-1] = '\0';

	assert(inet_ntop(AF_INET6, addr, addrstr, sizeof(addrstr)));

#if defined(_WIN32) || defined(_WIN64)
	/* Windows should take care of the route automatically */
	return 0;
#elif defined(__linux__)
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "ip -6 ro add default via %s\n", addrstr);
#else
	snprintf(cmdstr, sizeof(cmdstr)-1,
	         "route add -inet6 default %s\n", addrstr);
#endif
	ret = system(cmdstr);

	return ret;
}
