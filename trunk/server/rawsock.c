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

int
rawsock_init(int family, int protocol, int *err)
{
	int domain = 0;
	int ret;

#if defined(_WIN32) || defined(_WIN64)
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	ret = WSAStartup(wVersionRequested, &wsaData);
	if (ret) {
		/* Couldn't find WinSock DLL */
		return -1;
	}

	if (LOBYTE(wsaData.wVersion) != 2 ||
	    HIBYTE(wsaData.wVersion) != 2) {
		/* Version mismatch, requested version not found */
		return -1;
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
		return -1;
	}

	ret = socket(domain, SOCK_RAW, protocol);
	if (ret == -1) {
		*err = GetLastError();
	}

	return ret;
}

int
rawsock_wait_for_writable(int sockfd, int waitms, int *err)
{
	fd_set wfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&wfds);
	FD_SET(sockfd, &wfds);

	tv.tv_sec = waitms / 1000;
	tv.tv_usec = (waitms % 1000) * 1000;

	ret = select(sockfd+1, NULL, &wfds, NULL, &tv);
	if (ret == -1) {
		*err = GetLastError();
		return -1;
	}

	if (FD_ISSET(sockfd, &wfds)) {
		return 1;
	}

	return 0;
}

int
rawsock_sendto(int sockfd, const void *buf, int offset, int len,
               const struct sockaddr *dest_addr, socklen_t addrlen,
               int *err)
{
	int ret;

	ret = sendto(sockfd, buf+offset, len, 0, dest_addr, addrlen);
	if (ret == -1) {
		*err = GetLastError();
	}

	return ret;
}

int
rawsock_wait_for_readable(int sockfd, int waitms, int *err)
{
	fd_set rfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	tv.tv_sec = waitms / 1000;
	tv.tv_usec = (waitms % 1000) * 1000;

	ret = select(sockfd+1, &rfds, NULL, NULL, &tv);
	if (ret == -1) {
		*err = GetLastError();
		return -1;
	}

	if (FD_ISSET(sockfd, &rfds)) {
		return 1;
	}

	return 0;
}

int
rawsock_recvfrom(int socket, void *buf, int offset, int len,
                 struct sockaddr *src_addr, socklen_t *addrlen,
                 int *err)
{
	int ret;

	ret = recvfrom(socket, buf+offset, len, 0, src_addr, addrlen);
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
rawsock_destroy(int sockfd)
{
	closesocket(sockfd);

#if defined(_WIN32) || defined(_WIN64)
	WSACleanup();
#endif
}
