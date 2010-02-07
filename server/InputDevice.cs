/**
 *  Nabla - Automatic IP Tunneling and Connectivity
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

namespace Nabla {
	public abstract class InputDevice {
		public abstract void SetSessionManager(SessionManager sessionManager);
		public abstract TunnelType[] GetSupportedTypes();
		public abstract void Start();
		public abstract void Stop();
		public abstract void SendPacket(Int64 tunnelId, byte[] data);

		public static IPEndPoint GetIPEndPoint(EndPoint ep) {
			IPEndPoint endPoint = (IPEndPoint) ep;
			if (endPoint.AddressFamily == AddressFamily.InterNetworkV6) {
				byte[] addrBytes = endPoint.Address.GetAddressBytes();

				bool isIPv4Address = true;
				for (int i=0; i<12; i++) {
					if (i<10 && addrBytes[i] != 0x00) {
						isIPv4Address = false;
						break;
					} else if (i>=10 && addrBytes[i] != 0xff) {
						isIPv4Address = false;
						break;
					}
				}

				if (isIPv4Address) {
					/* IPv4 address in form ::ffff:x.x.x.x, replace IPEndPoint */
					byte[] ipaddr = new byte[4];
					Array.Copy(addrBytes, 12, ipaddr, 0, 4);
					endPoint = new IPEndPoint(new IPAddress(ipaddr), endPoint.Port);
				}
			}
			return endPoint;
		}
	}
}
