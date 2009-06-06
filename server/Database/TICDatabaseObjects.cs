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

namespace Nabla.Database {
	public class TICUserInfo {
		public string UserName;
		public string Password;
		public string FullName;
	}

	public class TICTunnelInfo {
		public int TunnelId;
		public string Type;

		public IPAddress IPv6EndPoint;
		public IPAddress IPv6POP;
		public int IPv6PrefixLength;

		public int TunnelMTU;
		public string TunnelName;

		public string POPId;
		public string IPv4Endpoint;
		public IPAddress IPv4POP;

		public bool UserState;
		public bool AdminState;

		public string Password;
		public int HeartbeatInterval;

		public override string ToString() {
			string ret = "";

			ret += "TunnelId: T" + TunnelId + "\n";
			ret += "Type: " + Type + "\n";
			ret += "IPv6 Endpoint: " + IPv6EndPoint + "\n";
			ret += "IPv6 POP: " + IPv6POP + "\n";
			ret += "IPv6 PrefixLength: " + IPv6PrefixLength + "\n";
			ret += "Tunnel MTU: " + TunnelMTU + "\n";
			ret += "Tunnel Name: " + TunnelName + "\n";
			ret += "POP Id: " + POPId + "\n";
			ret += "IPv4 Endpoint: " + IPv4Endpoint + "\n";
			ret += "IPv4POP: " + IPv4POP + "\n";
			ret += "UserState: " + (UserState ? "enabled" : "disabled") + "\n";
			ret += "AdminState: " + (AdminState ? "enabled" : "disabled") + "\n";
			ret += "Password: " + Password + "\n";
			ret += "Heartbeat_Interval: " + HeartbeatInterval + "\n";

			return ret;
		}
	}

	public class TICRouteInfo {
		public int RouteId;
		public IPAddress IPv6Prefix;
		public int IPv6PrefixLength;
		public string Description;
		public DateTime Created;
		public DateTime LastModified;
		public bool UserState;
		public bool AdminState;

		public override string ToString() {
			string ret = "";

			ret += "RouteId: R" + RouteId + "\n";
			ret += "Prefix: " + IPv6Prefix + "/" + IPv6PrefixLength + "\n";
			ret += "Description: " + Description + "\n";
			ret += "Created: " + Created.ToString("s").Replace("T", " ") + "\n";
			ret += "LastModified: " + LastModified.ToString("s").Replace("T", " ") + "\n";
			ret += "UserState: " + (UserState ? "enabled" : "disabled") + "\n";
			ret += "AdminState: " + (AdminState ? "enabled" : "disabled") + "\n";

			return ret;
		}
	}

	public class TICPopInfo {
		public string POPId;
		public string City;
		public string Country;
		public IPAddress IPv4;
		public IPAddress IPv6;
		public bool HeartbeatSupport;
		public bool TincSupport;
		public string MulticastSupport;
		public string ISPShort;
		public string ISPName;
		public string ISPWebsite;
		public int ISPASNumber;
		public string ISPLIRId;

		public override string ToString() {
			string ret = "";

			ret += "POPId: " + POPId + "\n";
			ret += "City: " + City + "\n";
			ret += "Country: " + Country + "\n";
			ret += "IPv4: " + IPv4 + "\n";
			ret += "IPv6: " + IPv6 + "\n";
			ret += "Heartbeat Support: " + (HeartbeatSupport ? "Y" : "N") + "\n";
			ret += "Tinc Support: " + (TincSupport ? "Y" : "N") + "\n";
			ret += "Multicast Support: " + MulticastSupport + "\n";
			ret += "ISP Short: " + ISPShort + "\n";
			ret += "ISP Name: " + ISPName + "\n";
			ret += "ISP ASN: AS" + ISPASNumber + "\n";
			ret += "ISP LIR: " + ISPLIRId + "\n";

			return ret;
		}
	}
}
