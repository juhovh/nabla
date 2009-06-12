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
using System.Threading;
using System.Collections.Generic;
using Nabla.Sockets;

namespace Nabla {
	public class IPConfig {
		public readonly IPAddress Address;
		public readonly int PrefixLength;
		public readonly IPAddress DefaultRoute;

		public IPConfig(IPAddress addr, int prefixlen, IPAddress route) {
			if (addr.AddressFamily == AddressFamily.InterNetwork) {
				if (prefixlen < 0 || prefixlen > 32) {
					throw new Exception("Subnet prefix length " + prefixlen + " invalid for family " + addr.AddressFamily);
				}
			} else if (addr.AddressFamily == AddressFamily.InterNetworkV6) {
				if (prefixlen < 0 || prefixlen > 128) {
					throw new Exception("Subnet prefix length " + prefixlen + " invalid for family " + addr.AddressFamily);
				}
			} else {
				throw new Exception("Unknown address family " + addr.AddressFamily);
			}

			if (addr != null && route != null && addr.AddressFamily != route.AddressFamily) {
				throw new Exception("Address families of the the address and route don't match");
			}

			Address = addr;
			PrefixLength = prefixlen;
			DefaultRoute = route;
		}

		public bool AddressInSubnet(IPAddress addr) {
			if (addr.AddressFamily != Address.AddressFamily) {
				return false;
			}

			byte[] b1 = addr.GetAddressBytes();
			byte[] b2 = Address.GetAddressBytes();
			int prefixlen = PrefixLength;

			for (int i=0; i <= (prefixlen-1)/8; i++) {
				if (i < prefixlen/8) {
					/* Full bytes compared */
					if (b1[i] != b2[i]) {
						return false;
					}
				} else {
					/* number of discarded bits */
					int disc = 8 - (prefixlen % 8);
					if ((b1[i] >> disc) != (b2[i] >> disc)) {
						return false;
					}
				}
			}

			return true;
		}
	}
}
