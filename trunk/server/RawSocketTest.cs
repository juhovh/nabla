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
using System.Net.Sockets;
using Nabla.Sockets;

public class RawSocketTest {
	private static void Main(string[] args) {
		if (args.Length < 1) {
			Console.WriteLine("Give the interface name as an argument");
			return;
		}

		byte[] address = RawSocket.GetHardwareAddress(args[0]);
		if (address != null) {
			Console.WriteLine("Got address: {0}",
				BitConverter.ToString(address).Replace('-', ':').ToLower());
		}

		RawSocket rawSocket =
			RawSocket.GetRawSocket(args[0], AddressFamily.DataLink, 0x0800, 100);
		byte[] buf = new byte[2048];
		rawSocket.Send(getTCPSyn());
		Console.WriteLine("Received {0} bytes", rawSocket.Receive(buf));
	}

	private static byte[] getTCPSyn() {
		return new byte[] {
			0x00, 0x13, 0x10, 0x7b, 0x17, 0x61, 0x00, 0x1b,
			0xb9, 0xbc, 0x37, 0x92, 0x08, 0x00, 0x45, 0x10,
			0x00, 0x3c, 0xb2, 0x7e, 0x40, 0x00, 0x40, 0x06,
			0x82, 0x46, 0xc0, 0xa8, 0x01, 0x0b, 0x50, 0xf7,
			0xf3, 0x3c, 0xb9, 0x18, 0x00, 0x50, 0x48, 0x92,
			0xd3, 0x10, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
			0x16, 0xd0, 0xea, 0x83, 0x00, 0x00, 0x02, 0x04,
			0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x0a, 0x4c,
			0x61, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
			0x03, 0x06 };
	}
}

