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
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Nabla {
	public class TunnelSession {
		public readonly TunnelType TunnelType;
		public readonly AddressFamily AddressFamily;
		public IPEndPoint EndPoint = null;

		public readonly IPAddress LocalAddress = null;
		public readonly IPAddress RemoteAddress = null;
		public readonly string Password = null;
		public DateTime LastAlive;

		private TunnelSession(TunnelType type) {
			TunnelType = type;
			switch (type) {
			case TunnelType.IPv4inIPv4:
			case TunnelType.IPv4inIPv6:
			case TunnelType.AyiyaIPv4:
				AddressFamily = AddressFamily.InterNetwork;
				break;
			case TunnelType.IPv6inIPv4:
			case TunnelType.IPv6inIPv6:
			case TunnelType.Heartbeat:
			case TunnelType.AyiyaIPv6:
				AddressFamily = AddressFamily.InterNetworkV6;
				break;
			default:
				throw new Exception("Unknown tunnel type: " + type);
			}
			LastAlive = DateTime.Now;
		}

		public TunnelSession(TunnelType type, IPEndPoint endPoint) : this(type) {
			switch (type) {
			case TunnelType.Heartbeat:
			case TunnelType.AyiyaIPv4:
			case TunnelType.AyiyaIPv6:
				throw new Exception("A dynamic tunnel type " + type + " can't be configured as static");
			}

			EndPoint = endPoint;
		}

		public TunnelSession(TunnelType type, IPAddress localAddress, IPAddress remoteAddress, string password) : this(type) {
			switch (type) {
			case TunnelType.IPv4inIPv4:
			case TunnelType.IPv4inIPv6:
			case TunnelType.IPv6inIPv4:
			case TunnelType.IPv6inIPv6:
				throw new Exception("A static tunnel type " + type + " can't be configured as dynamic");
			}

			LocalAddress = localAddress;
			RemoteAddress = remoteAddress;
			Password = password;
		}

		public override string ToString() {
			string ret = "";

			ret += "TunnelType: " + TunnelType + "\n";
			ret += "AddressFamily: " + AddressFamily + "\n";
			ret += "EndPoint: " + EndPoint + "\n";
			ret += "LocalAddress: " + LocalAddress + "\n";
			ret += "RemoteAddress: " + RemoteAddress + "\n";
			ret += "Password: " + Password + "\n";
			ret += "LastAlive: " + LastAlive.ToString("s");

			return ret;
		}
	}
}
