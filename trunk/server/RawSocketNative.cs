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

using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Nabla {
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
		private static extern int rawsock_bind(IntPtr sock, byte[] addr, int addrlen, ref int err);

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
		private static extern void rawsock_get_address(IntPtr sock, ref IntPtr address, ref int addrlen);

		[DllImport("rawsock")]
		private static extern void rawsock_destroy(IntPtr sock);


		public RawSocketNative(string ifname, AddressFamily addressFamily, int protocol, int waitms) {
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

		public override void Bind(EndPoint localEP) {
			SocketAddress socketAddress = localEP.Serialize();

			byte[] buf = new byte[socketAddress.Size];
			for (int i=0; i<socketAddress.Size; i++)
				buf[i] = socketAddress[i];

			int errno = 0;
			int ret = rawsock_bind(_sock, buf, buf.Length, ref errno);
			if (ret == -1) {
				throw new Exception("Error writing to raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}
		}

		public override bool WaitForWritable() {
			int errno = 0;

			int ret = rawsock_wait_for_writable(_sock, _waitms, ref errno);
			if (ret == -1) {
				throw new Exception("Error selecting raw socket: " + rawsock_strerror(errno) + " (" + errno + ")");
			}

			return (ret == 1) ? true : false;
		}

		public override int SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP) {
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

		public override int ReceiveFrom(byte[] buffer, int offset, int size, ref EndPoint remoteEP) {
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

			if (remoteEP != null) {
				AddressFamily family = (AddressFamily) rawsock_get_family(buf);
				SocketAddress socketAddress = new SocketAddress(family, length);
				for (int i=2; i<socketAddress.Size; i++)
					socketAddress[i] = buf[i];
				remoteEP = remoteEP.Create(socketAddress);
			}

			return ret;
		}

		public override byte[] GetAddress() {
			IntPtr address = IntPtr.Zero;
			int addrlen = 0;

			rawsock_get_address(_sock, ref address, ref addrlen);
			if (address == IntPtr.Zero || addrlen == 0)
				return null;

			byte[] array = new byte[addrlen];
			Marshal.Copy(address, array, 0, addrlen);

			return array;
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

