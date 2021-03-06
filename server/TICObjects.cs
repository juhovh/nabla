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

namespace Nabla {
	public class TICTunnelInfo {
		public readonly Int64 TunnelId;
		public readonly string Type;

		public IPAddress IPv6Endpoint;
		public IPAddress IPv6POP;
		public Int64 IPv6PrefixLength;

		public Int64 TunnelMTU;
		public string TunnelName;

		public string POPId;
		public string IPv4Endpoint;
		public IPAddress IPv4POP;

		public bool UserEnabled;
		public bool AdminEnabled;

		public string Password;
		public Int64 HeartbeatInterval;

		public TICTunnelInfo(Int64 id, string endpoint) {
			TunnelId = id;
			if (endpoint.Equals("heartbeat")) {
				Type = "6in4-heartbeat";
			} else if (endpoint.Equals("ayiya")) {
				Type = "ayiya";
			} else {
				try {
					IPAddress addr = IPAddress.Parse(endpoint);
					if (addr.AddressFamily == AddressFamily.InterNetwork) {
						Type = "6in4";
					} else {
						Type = "4in6";
					}
				} catch (Exception) {
					Type = "unknown";
				}
			}
		}

		public override string ToString() {
			string ret = "";

			ret += "TunnelId: T" + TunnelId + "\n";
			ret += "Type: " + Type + "\n";
			ret += "IPv6 Endpoint: " + IPv6Endpoint + "\n";
			ret += "IPv6 POP: " + IPv6POP + "\n";
			ret += "IPv6 PrefixLength: " + IPv6PrefixLength + "\n";
			ret += "Tunnel MTU: " + TunnelMTU + "\n";
			ret += "Tunnel Name: " + TunnelName + "\n";
			ret += "POP Id: " + POPId + "\n";
			ret += "IPv4 Endpoint: " + IPv4Endpoint + "\n";
			ret += "IPv4 POP: " + IPv4POP + "\n";
			ret += "UserState: " + (UserEnabled ? "enabled" : "disabled") + "\n";
			ret += "AdminState: " + (AdminEnabled ? "enabled" : "disabled") + "\n";
			ret += "Password: " + Password + "\n";
			ret += "Heartbeat_Interval: " + HeartbeatInterval + "\n";

			return ret;
		}
	}

	public class TICRouteInfo {
		public Int64 RouteId;

		public IPAddress IPv6Prefix;
		public Int64 IPv6PrefixLength;
		public string Description;
		public DateTime Created;
		public DateTime LastModified;
		public bool UserEnabled;
		public bool AdminEnabled;

		public TICRouteInfo(Int64 routeId) {
			RouteId = routeId;
		}

		public override string ToString() {
			string ret = "";

			ret += "RouteId: R" + RouteId + "\n";
			ret += "Prefix: " + IPv6Prefix + "/" + IPv6PrefixLength + "\n";
			ret += "Description: " + Description + "\n";
			ret += "Created: " + Created.ToString("s").Replace("T", " ") + "\n";
			ret += "LastModified: " + LastModified.ToString("s").Replace("T", " ") + "\n";
			ret += "UserState: " + (UserEnabled ? "enabled" : "disabled") + "\n";
			ret += "AdminState: " + (AdminEnabled ? "enabled" : "disabled") + "\n";

			return ret;
		}
	}

	public class TICPopInfo {
		public string POPId;

		public string City;
		public string Country;
		public IPAddress IPv4;
		public IPAddress IPv6;
		public string HeartbeatSupport;
		public string TincSupport;
		public string MulticastSupport;
		public string ISPShort;
		public string ISPName;
		public string ISPWebsite;
		public Int64 ISPASNumber;
		public string ISPLIRId;

		public TICPopInfo(string id) {
			POPId = id;
		}

		public override string ToString() {
			string ret = "";

			ret += "POPId: " + POPId + "\n";
			ret += "City: " + City + "\n";
			ret += "Country: " + Country + "\n";
			ret += "IPv4: " + IPv4 + "\n";
			ret += "IPv6: " + IPv6 + "\n";
			ret += "Heartbeat Support: " + HeartbeatSupport + "\n";
			ret += "Tinc Support: " + TincSupport + "\n";
			ret += "Multicast Support: " + MulticastSupport + "\n";
			ret += "ISP Short: " + ISPShort + "\n";
			ret += "ISP Name: " + ISPName + "\n";
			ret += "ISP ASN: AS" + ISPASNumber + "\n";
			ret += "ISP LIR: " + ISPLIRId + "\n";

			return ret;
		}
	}
}
