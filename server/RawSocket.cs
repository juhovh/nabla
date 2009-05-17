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

public abstract class RawSocket {
	public static RawSocket GetRawSocket(AddressFamily addressFamily, int protocol, int waitms) {
		return new RawSocketNative(addressFamily, protocol, waitms);
	}

	public abstract void Bind(EndPoint localEP);

	public abstract bool WaitForWritable();
	public abstract int SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP);

	public int SendTo(byte[] buffer, int size, EndPoint remoteEP) {
		return SendTo(buffer, 0, size, remoteEP);
	}
	public int SendTo(byte[] buffer, EndPoint remoteEP) {
		return SendTo(buffer, buffer.Length, remoteEP);
	}

	public abstract bool WaitForReadable();
	public abstract int ReceiveFrom(byte[] buffer, int offset, int size, ref EndPoint remoteEP);

	public int ReceiveFrom(byte[] buffer, int size, ref EndPoint remoteEP) {
		return ReceiveFrom(buffer, 0, size, ref remoteEP);
	}
	public int ReceiveFrom(byte[] buffer, ref EndPoint remoteEP) {
		return ReceiveFrom(buffer, buffer.Length, ref remoteEP);
	}

	public abstract byte[] GetAddress();
}

