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

public class RawSocketTest {
	private static void Main(string[] args) {
		RawSocket rawSocket =
			RawSocket.GetRawSocket("eth0", AddressFamily.DataLink, 0x86dd, 100);

		byte[] address = rawSocket.GetAddress();
		if (address != null) {
			Console.Write("Got address:");
			for (int i=0; i<address.Length; i++)
				Console.Write(" 0x{0:x}", address[i]);
			Console.WriteLine("");
		}
	}
}

