/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009-2010  Juho Vähä-Herttua
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
using System.Collections.Generic;
using Nabla.Sockets;

namespace Nabla {
	public abstract class InputDevice {
		public abstract void SetSessionManager(SessionManager sessionManager);
		public abstract TunnelType GetSupportedType();
		public abstract void Start();
		public abstract void Stop();
		public abstract void SendPacket(Int64 tunnelId, byte[] data, int offset, int length);

		protected static IPAddress GetBindAddress(string deviceName, bool ipv6) {
			IPAddress bindAddr = null;

			Dictionary<IPAddress, IPAddress> addrs = RawSocket.GetIPAddresses(deviceName);
			if (ipv6) {
				foreach (IPAddress addr in addrs.Keys) {
					if (addr.AddressFamily == AddressFamily.InterNetworkV6 && !addr.IsIPv6LinkLocal) {
						bindAddr = addr;
						break;
					}
				}
			} else {
				foreach (IPAddress addr in addrs.Keys) {
					if (addr.AddressFamily == AddressFamily.InterNetwork) {
						bindAddr = addr;
						break;
					}
				}
			}

			return bindAddr;
		}
	}
}
