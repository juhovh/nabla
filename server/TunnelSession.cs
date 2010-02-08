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
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Nabla {
	public class TunnelSession {
		public readonly Int64 TunnelId;
		public readonly TunnelType TunnelType;
		public IPEndPoint EndPoint = null;

		public readonly string Password = null;
		public DateTime LastAlive;

		public TunnelSession(Int64 id, TunnelType type) {
			TunnelId = id;
			TunnelType = type;
			LastAlive = DateTime.Now;
		}

		public TunnelSession(Int64 id, TunnelType type, string password) : this(id, type) {
			Password = password;
		}

		public TunnelSession(Int64 id, TunnelType type, IPEndPoint endPoint) : this(id, type) {
			EndPoint = endPoint;
		}

		public override string ToString() {
			string ret = "";

			ret += "TunnelId: " + TunnelId + "\n";
			ret += "TunnelType: " + TunnelType + "\n";
			ret += "EndPoint: " + EndPoint + "\n";
			ret += "Password: " + Password + "\n";
			ret += "LastAlive: " + LastAlive.ToString("s");

			return ret;
		}
	}
}
