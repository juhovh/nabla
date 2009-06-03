/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace Nabla.Sockets {
	public class RawSocketNative : RawSocket {
		private bool _disposed = false;
		private IntPtr _sock;
		private int _waitms;

		[DllImport("rawsock")]
		private static extern int rawsock_get_family(byte[] sockaddr);

		[DllImport("rawsock")]
		private static extern int rawsock_set_family(byte[] sockaddr, int family);

		[DllImport("rawsock")]
		private static extern IntPtr rawsock_init(string ifname, int family, int protocol, ref int err);

		[DllImport("rawsock")]
		private static extern int rawsock_wait_for_writable(IntPtr sock, int waitms, ref int err);

		[DllImport("rawsock")]
		private static extern int rawsock_sendto(IntPtr sock, byte[] buf, int offset, int len, byte[] sockaddr, int addrlen, ref int err);

		[DllImport("rawsock")]
		private static extern int rawsock_wait_for_readable(IntPtr sock, int waitms, ref int err);

		[DllImport("rawsock")]
		private static extern int rawsock_recvfrom(IntPtr sock, byte[] buf, int offset, int len, byte[] sockaddr, ref int addrlen, ref int err);

		[DllImport("rawsock")]
		private static extern string rawsock_strerror(int errno);

		[DllImport("rawsock")]
		private static extern void rawsock_destroy(IntPtr sock);

		[DllImport("rawsock")]
		private static extern int rawsock_get_hardware_address(string ifname, byte[] address, ref int addrlen, ref int err);


		public static new byte[] GetHardwareAddress(string ifname) {
			byte[] address = new byte[12];
			int addrlen = 12;
			int ret, err = 0;

			ret = rawsock_get_hardware_address(ifname, address, ref addrlen, ref err);
			if (ret == -1) {
				throw new Exception("Error getting hardware address");
			}

			byte[] retaddr = new byte[addrlen];
			Array.Copy(address, 0, retaddr, 0, addrlen);

			return retaddr;
		}

		public static new Dictionary<IPAddress, IPAddress> GetIPAddresses(string ifname) {
			throw new Exception("Getting IP addresses not implemented in rawsock");
		}

		public RawSocketNative(string ifname, AddressFamily addressFamily, int protocol, int waitms) : base(ifname) {
			int errno = 0;
			int family;

			switch (addressFamily) {
			case AddressFamily.InterNetwork:
				family = 0;
				break;
			case AddressFamily.InterNetworkV6:
				family = 1;
				break;
			case AddressFamily.DataLink:
				family = 2;
				break;
			default:
				throw new Exception("Address family '" + addressFamily + "' not supported");
			}

			_sock = rawsock_init(ifname, family, protocol, ref errno);
			if (_sock == IntPtr.Zero) {
				throw new Exception("Error initializing raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			_waitms = waitms;
		}

		public override bool WaitForWritable() {
			int errno = 0;

			int ret = rawsock_wait_for_writable(_sock, _waitms, ref errno);
			if (ret == -1) {
				throw new Exception("Error selecting raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			return (ret == 1) ? true : false;
		}

		public override int SendTo(byte[] buffer, int offset, int size, IPEndPoint remoteEP) {
			int errno = 0;
			byte[] buf = null;
			int length = 0;
			int ret;

			if (remoteEP != null) {
				SocketAddress socketAddress = remoteEP.Serialize();

				buf = new byte[socketAddress.Size];
				for (int i=2; i<socketAddress.Size; i++)
					buf[i] = socketAddress[i];
				ret = rawsock_set_family(buf, (int) socketAddress.Family);
				if (ret < 0) {
					throw new Exception("Address family " + socketAddress.Family + " of endpoint unsupported");
				}

				length = buf.Length;
			}

			ret = rawsock_sendto(_sock, buffer, offset, size, buf, length, ref errno);
			if (ret == -1) {
				throw new Exception("Error writing to raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			return ret;
		}

		public override bool WaitForReadable() {
			int errno = 0;

			int ret = rawsock_wait_for_readable(_sock, _waitms, ref errno);
			if (ret == -1) {
				throw new Exception("Error selecting raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			return (ret == 1) ? true : false;
		}

		public override int ReceiveFrom(byte[] buffer, int offset, int size, ref IPEndPoint remoteEP) {
			int errno = 0;
			byte[] buf = null;
			int length = 0;
			int ret;

			if (remoteEP != null) {
				SocketAddress socketAddress = remoteEP.Serialize();

				/* 128 bytes Should Be Enough(tm) for everything (Linux sockaddr_storage) */
				buf = new byte[128];
				for (int i=2; i<socketAddress.Size; i++)
					buf[i] = socketAddress[i];
				ret = rawsock_set_family(buf, (int) socketAddress.Family);
				if (ret < 0) {
					throw new Exception("Address family " + socketAddress.Family + " of endpoint unsupported");
				}

				length = buf.Length;
			}

			ret = rawsock_recvfrom(_sock, buffer, offset, size, buf, ref length, ref errno);
			if (ret == -1) {
				throw new Exception("Error reading from raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			/* XX: Should there really be null check here? */
			if (remoteEP != null) {
				AddressFamily family = (AddressFamily) rawsock_get_family(buf);
				SocketAddress socketAddress = new SocketAddress(family, length);
				for (int i=2; i<socketAddress.Size; i++)
					socketAddress[i] = buf[i];
				remoteEP = (IPEndPoint) remoteEP.Create(socketAddress);
			}

			return ret;
		}

		public void Dispose() {
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// Managed resources can be disposed here
				}

				rawsock_destroy(_sock);
				_disposed = true;
			}
		}
	}
}

