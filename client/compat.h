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

#ifndef COMPAT_H
#define COMPAT_H

#include <unistd.h>

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>

/* Define Windows to be little endian */
#define BIG_ENDIAN 4321
#define LITTLE_ENDIAN 1234
#define BYTE_ORDER LITTLE_ENDIAN

#  define sleepms(x) Sleep(x)

/* Define missing inet_ntop and inet_pton from compat.c on Windows */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);

#  define INIT_SOCKETLIB(success) \
do { \
	WORD wVersionRequested; \
	WSADATA wsaData; \
	int ret; \
	wVersionRequested = MAKEWORD(2, 2); \
	ret = WSAStartup(wVersionRequested, &wsaData); \
	if (ret) { \
		/* Couldn't find WinSock DLL */ \
		success = 0; \
		break; \
	} \
	if (LOBYTE(wsaData.wVersion) != 2 || \
	    HIBYTE(wsaData.wVersion) != 2) { \
		/* Version mismatch, requested version not found */ \
		success = 0; \
		break; \
	} \
	success = 1; \
} while(0)

#  define CLOSE_SOCKETLIB(success) success = WSACleanup()

#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>

/* Include this as it knows quite a bit about endianess */
#include <arpa/nameser_compat.h>

#  define sleepms(x) usleep((x)*1000)
#  define closesocket close

#  define INIT_SOCKETLIB(success) success = 1
#  define CLOSE_SOCKETLIB(success) success = 1

#endif

#  ifndef IPPROTO_IPIP
#    define IPPROTO_IPIP 4
#  endif

#endif /* COMPAT_H */
