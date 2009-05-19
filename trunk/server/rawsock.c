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
#include <assert.h>

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define GetLastError WSAGetLastError
#else
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <string.h>
#  include <unistd.h>
#  include <errno.h>
#  define closesocket close
#  define GetLastError() errno
#endif

#if defined(__linux__)
#  include <sys/ioctl.h>
#  include <arpa/inet.h>
#  include <linux/if.h>
#  include <linux/if_arp.h>
#  include <linux/if_ether.h>
#  include <linux/if_packet.h>
#endif

#define FAMILY_IPv4    0
#define FAMILY_IPv6    1
#define FAMILY_PACKET  2

struct rawsock_s {
	int sockfd;
	char *ifname;
	int domain;

	char *address;
	int addrlen;
};
typedef struct rawsock_s rawsock_t;

int rawsock_get_hardware_address(const char *ifname, char *address, int *addrlen, int *err);

int
rawsock_get_family(struct sockaddr *saddr)
{
	assert(saddr);

	switch (saddr->sa_family) {
	case AF_INET:
		return 2;
	case AF_INET6:
		return 23;
#if defined(_WIN32) || defined(_WIN64)
#elif defined(__linux__)
	case AF_PACKET:
#elif defined(__sun__)
#else
	case AF_LINK:
#endif
		return 13;
	default:
		return -1;
	}
}

int
rawsock_set_family(struct sockaddr *saddr, int family)
{
	assert(saddr);

	switch (family) {
	case 2:
		saddr->sa_family = AF_INET;
		break;
	case 23:
		saddr->sa_family = AF_INET6;
		break;
	case 13:
#if defined(_WIN32) || defined(_WIN64)
		saddr->sa_family = AF_NETBIOS;
#elif defined(__linux__)
		saddr->sa_family = AF_PACKET;
#else
		saddr->sa_family = AF_LINK;
#endif
		break;
	default:
		return -1;
	}

	return 0;
}


rawsock_t *
rawsock_init(const char *ifname, int family, int protocol, int *err)
{
	rawsock_t *rawsock;
	int domain = 0;
	int ret;

#if defined(_WIN32) || defined(_WIN64)
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	ret = WSAStartup(wVersionRequested, &wsaData);
	if (ret) {
		/* Couldn't find WinSock DLL */
		*err = GetLastError();
		return NULL;
	}

	if (LOBYTE(wsaData.wVersion) != 2 ||
	    HIBYTE(wsaData.wVersion) != 2) {
		/* Version mismatch, requested version not found */
		*err = WSAEINVAL;
		return NULL;
	}
#endif

	switch (family) {
	case FAMILY_IPv4:
		domain = AF_INET;
		break;
	case FAMILY_IPv6:
		domain = AF_INET6;
		break;
	case FAMILY_PACKET:
#if defined(__linux__)
		if (!ifname) {
			*err = EINVAL;
			return NULL;
		}
		domain = AF_PACKET;
		protocol = htons(protocol);
		break;
#endif
	default:
		/* Unknown protocol family */
		return NULL;
	}

	ret = socket(domain, SOCK_RAW, protocol);
	if (ret == -1) {
		*err = GetLastError();
		return NULL;
	}

	if (rawsock_get_hardware_address(ifname, NULL, NULL, err) < 0) {
		return NULL;
	}

	rawsock = calloc(1, sizeof(rawsock_t));
	if (!rawsock) {
		return NULL;
	}

	rawsock->sockfd = ret;
	rawsock->domain = domain;
	if (ifname) {
		rawsock->ifname = strdup(ifname);
	}

	return rawsock;
}

int
rawsock_bind(rawsock_t *rawsock,
             const struct sockaddr *addr, socklen_t addrlen,
             int *err)
{
	int ret;

	assert(rawsock);

	ret = bind(rawsock->sockfd, addr, addrlen);
	if (ret == -1) {
		*err = GetLastError();
	}

	return ret;
}

int
rawsock_wait_for_writable(rawsock_t *rawsock, int waitms, int *err)
{
	fd_set wfds;
	struct timeval tv;
	int ret;

	assert(rawsock);

	FD_ZERO(&wfds);
	FD_SET(rawsock->sockfd, &wfds);

	tv.tv_sec = waitms / 1000;
	tv.tv_usec = (waitms % 1000) * 1000;

	ret = select(rawsock->sockfd+1, NULL, &wfds, NULL, &tv);
	if (ret == -1) {
		*err = GetLastError();
		return -1;
	}

	if (FD_ISSET(rawsock->sockfd, &wfds)) {
		return 1;
	}

	return 0;
}

int
rawsock_sendto(rawsock_t *rawsock, const void *buf, int offset, int len,
               struct sockaddr *dest_addr, socklen_t addrlen,
               int *err)
{
	int ret;

	assert(rawsock);

	ret = sendto(rawsock->sockfd, buf+offset, len, 0, dest_addr, addrlen);
	if (ret == -1) {
		*err = GetLastError();
	}

	return ret;
}

int
rawsock_wait_for_readable(rawsock_t *rawsock, int waitms, int *err)
{
	fd_set rfds;
	struct timeval tv;
	int ret;

	assert(rawsock);

	FD_ZERO(&rfds);
	FD_SET(rawsock->sockfd, &rfds);

	tv.tv_sec = waitms / 1000;
	tv.tv_usec = (waitms % 1000) * 1000;

	ret = select(rawsock->sockfd+1, &rfds, NULL, NULL, &tv);
	if (ret == -1) {
		*err = GetLastError();
		return -1;
	}

	if (FD_ISSET(rawsock->sockfd, &rfds)) {
		return 1;
	}

	return 0;
}

int
rawsock_recvfrom(rawsock_t *rawsock, void *buf, int offset, int len,
                 struct sockaddr *src_addr, socklen_t *addrlen,
                 int *err)
{
	int ret;

	assert(rawsock);

	ret = recvfrom(rawsock->sockfd, buf+offset, len, 0, src_addr, addrlen);
	if (ret == -1) {
		*err = GetLastError();
	}

	return ret;
}

char *
rawsock_strerror(int errnum)
{
	return strdup(strerror(errnum));
}

int
rawsock_get_hardware_address(const char *ifname, char *address, int *addrlen, int *err)
{
#if defined(__linux__)
	int sock;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int index;
	int ret;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		*err = errno;
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret == -1) {
		closesocket(sock);
		*err = errno;
		return -1;
	}
	index = ifr.ifr_ifindex;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	ret = bind(sock,
		   (const struct sockaddr *) &sll,
		   sizeof(sll));
	if (ret == -1) {
		closesocket(sock);
		*err = errno;
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (ret == -1) {
		closesocket(sock);
		*err = errno;
		return -1;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		closesocket(sock);
		*err = EINVAL;
		return -1;
	}

	if (addrlen) {
		if (!address || *addrlen < ETH_ALEN) {
			closesocket(sock);
			*err = EINVAL;
			return -1;
		}
		*addrlen = ETH_ALEN;
		memcpy(address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	}

	return 0;
#endif

	return -1;
}

void
rawsock_destroy(rawsock_t *rawsock)
{
	if (rawsock) {
		closesocket(rawsock->sockfd);
		free(rawsock->ifname);
		free(rawsock->address);
		free(rawsock);

#if defined(_WIN32) || defined(_WIN64)
		WSACleanup();
#endif
	}
}
