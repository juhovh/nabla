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
using System.Text;
using System.Security.Cryptography;

namespace Nabla.Database {
	public class UserInfo {
		public Int64 UserId;
		public bool Enabled;

		public string UserName;
		public string Password;
		public string TunnelPassword;
		public string FullName;

		public override string ToString() {
			string ret = "";
			ret += "UserId: " + UserId + "\n";
			ret += "Enabled: " + Enabled + "\n";

			ret += "UserName: " + UserName + "\n";
			ret += "TunnelPassword: " + TunnelPassword + "\n";
			ret += "FullName: " + FullName;
			return ret;
		}
	}

	public class TunnelInfo {
		public Int64 TunnelId;
		public Int64 OwnerId;
		public DateTime Created;
		public DateTime LastModified;
		public bool Enabled;

		public string Name;
		public string Type;
		public string Endpoint;
		public bool UserEnabled;

		public string Password {
			get {
				MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
				byte[] bytes = Encoding.UTF8.GetBytes("" + TunnelId + OwnerId + Created + Name + Type + Endpoint);
				byte[] hashBytes = md5.ComputeHash(bytes);
				string hashStr = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
				return hashStr;
			}
		}

		public override string ToString() {
			string ret = "";
			ret += "TunnelId: " + TunnelId + "\n";
			ret += "OwnerId: " + OwnerId + "\n";
			ret += "Created: " + Created + "\n";
			ret += "LastModified: " + LastModified + "\n";
			ret += "Enabled: " + Enabled + "\n";

			ret += "Name: " + Name + "\n";
			ret += "Endpoint: " + Endpoint + "\n";
			ret += "UserEnabled: " + UserEnabled + "\n";
			ret += "Password: " + Password;
			return ret;
		}
	}

	public class RouteInfo {
		public Int64 RouteId;
		public Int64 OwnerId;
		public Int64 TunnelId;
		public DateTime Created;
		public DateTime LastModified;
		public bool Enabled;

		public string Description;
		public bool UserEnabled;

		public override string ToString() {
			string ret = "";
			ret += "RouteId: " + RouteId + "\n";
			ret += "OwnerId: " + OwnerId + "\n";
			ret += "TunnelId: " + TunnelId + "\n";
			ret += "Created: " + Created + "\n";
			ret += "LastModified: " + LastModified + "\n";
			ret += "Enabled: " + Enabled + "\n";

			ret += "Description: " + Description + "\n";
			ret += "UserEnabled: " + UserEnabled + "\n";
			return ret;
		}
	}
}
