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

#define FAMILY_IPv4 0
#define FAMILY_IPv6 1

struct rawsock_s {
	int sockfd;
	int domain;

	char *address;
	int addrlen;
};
typedef struct rawsock_s rawsock_t;

rawsock_t *
rawsock_init(int family, int protocol, int *err)
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
		return NULL;
	}

	if (LOBYTE(wsaData.wVersion) != 2 ||
	    HIBYTE(wsaData.wVersion) != 2) {
		/* Version mismatch, requested version not found */
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
	default:
		/* Unknown protocol family */
		return NULL;
	}

	ret = socket(domain, SOCK_RAW, protocol);
	if (ret == -1) {
		*err = GetLastError();
		return NULL;
	}

	rawsock = calloc(1, sizeof(rawsock_t));
	if (!rawsock) {
		return NULL;
	}

	rawsock->sockfd = ret;
	rawsock->domain = domain;

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
               const struct sockaddr *dest_addr, socklen_t addrlen,
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

void
rawsock_get_address(rawsock_t *rawsock, char **address, int *addrlen)
{
	assert(rawsock);

	*address = rawsock->address;
	*addrlen = rawsock->addrlen;
}

void
rawsock_destroy(rawsock_t *rawsock)
{
	if (rawsock) {
		closesocket(rawsock->sockfd);

		if (rawsock->address) {
			free(rawsock->address);
		}
		free(rawsock);

#if defined(_WIN32) || defined(_WIN64)
		WSACleanup();
#endif
	}
}
