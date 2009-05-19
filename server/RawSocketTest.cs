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
using Nabla.RawSocket;

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
		while (true) {
			Console.WriteLine("Received {0} bytes", rawSocket.Receive(buf));
		}
	}
}
