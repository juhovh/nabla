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
using System.Data;
using System.Data.SQLite;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Nabla.Database {
	public class TICDatabase {
		private SQLiteConnection _connection;

		public TICDatabase(string dbName) {
			_connection = new SQLiteConnection("Data Source=" + dbName);
			_connection.Open();
		}

		public void Cleanup() {
			_connection.Close();
			_connection.Dispose();
		}

		public void CreateTables() {
			string userString = "CREATE TABLE tic_users (" +
				"id integer primary key autoincrement" +
				", username varchar(32)" +
				", password varchar(32)" +
				", fullname varchar(128))";
			string tunnelString = "CREATE TABLE tic_tunnels (" +
				"id integer primary key autoincrement" +
				", ownerid integer" +
				", ipv6endpoint varchar(39)" +
				", ipv6pop varchar(39)" +
				", ipv6prefixlen integer" +
				", mtu integer" +
				", name varchar(64)" +
				", popid varchar(8)" +
				", ipv4endpoint varchar(15)" +
				", ipv4pop varchar(15)" +
				", userstate varchar(8)" +
				", adminstate varchar(8)" +
				", password varchar(32)" +
				", beatinterval integer)";
			string routeString = "CREATE TABLE tic_routes (" +
				"id integer primary key autoincrement" +
				", ownerid integer" +
				", tunnelid integer" +
				", ipv6prefix varchar(39)" +
				", ipv6prefixlen integer" +
				", description varchar(512)" +
				", created datetime" +
				", lastmodified datetime" +
				", userstate varchar(8)" +
				", adminstate varchar(8))";
			string popString = "CREATE TABLE tic_pops (" +
				"id varchar(8) primary key" +
				", city varchar(32)" +
				", country varchar(32)" +
				", ipv4 varchar(15)" +
				", ipv6 varchar(39)" +
				", heartbeat boolean" +
				", tinc boolean" +
				", multicast varchar(8)" +
				", ispshort varchar(8)" +
				", ispname varchar(128)" +
				", ispwebsite varchar(128)" +
				", ispasn integer" +
				", isplir varchar(32))";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = userString;
				command.ExecuteNonQuery();
				command.CommandText = tunnelString;
				command.ExecuteNonQuery();
				command.CommandText = routeString;
				command.ExecuteNonQuery();
				command.CommandText = popString;
				command.ExecuteNonQuery();
			}
		}

		public void AddUserInfo(TICUserInfo userInfo) {
			string tableName = "tic_users";

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] pwBytes = Encoding.UTF8.GetBytes(userInfo.Password);
			byte[] pwHashBytes = md5.ComputeHash(pwBytes);
			string pwHash = BitConverter.ToString(pwHashBytes).Replace("-", "").ToLower();

			string commandString = "INSERT INTO " + tableName +
				" (username, password, fullname) VALUES (" +
				"'" + userInfo.UserName + "', " +
				"'" + pwHash + "', " +
				"'" + userInfo.FullName + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void AddTunnelInfo(TICTunnelInfo tunnelInfo) {
			string tableName = "tic_tunnels";

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] pwBytes = Encoding.UTF8.GetBytes(tunnelInfo.Password);
			byte[] pwHashBytes = md5.ComputeHash(pwBytes);
			string pwHash = BitConverter.ToString(pwHashBytes).Replace("-", "").ToLower();

			string commandString = "INSERT INTO " + tableName +
				" (ownerid" +
				", ipv6endpoint, ipv6pop, ipv6prefixlen" +
				", mtu, name, popid" +
				", ipv4endpoint, ipv4pop" +
				", userstate, adminstate" +
				", password, beatinterval" +
				") VALUES (" +
				tunnelInfo.OwnerId + ", " +

				"'" + tunnelInfo.IPv6Endpoint + "', " +
				"'" + tunnelInfo.IPv6POP + "', " +
				tunnelInfo.IPv6PrefixLength + ", " +

				tunnelInfo.TunnelMTU + ", " +
				"'" + tunnelInfo.TunnelName + "', " +

				"'" + tunnelInfo.POPId + "', " +
				"'" + tunnelInfo.IPv4Endpoint + "', " +
				"'" + tunnelInfo.IPv4POP + "', " +

				"'" + (tunnelInfo.UserEnabled ? "enabled" : "disabled") + "', " +
				"'" + (tunnelInfo.AdminEnabled ? "enabled" : "disabled") + "', " +

				"'" + pwHash + "', " +
				tunnelInfo.HeartbeatInterval + ")";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void AddRouteInfo(TICRouteInfo routeInfo) {
			string tableName = "tic_routes";

			routeInfo.Created = DateTime.UtcNow;
			routeInfo.LastModified = DateTime.UtcNow;

			string commandString = "INSERT INTO " + tableName +
				" (ownerid, tunnelid" +
				", ipv6prefix, ipv6prefixlen" +
				", description" +
				", created, lastmodified" +
				", userstate, adminstate" +
				") VALUES (" +
				routeInfo.OwnerId + ", " +
				routeInfo.TunnelId + ", " +

				"'" + routeInfo.IPv6Prefix + "', " +
				routeInfo.IPv6PrefixLength + ", " +

				"'" + routeInfo.Description + "', " +

				"datetime('" + routeInfo.Created.ToString("s") + "'), " +
				"datetime('" + routeInfo.LastModified.ToString("s") + "'), " +

				"'" + (routeInfo.UserEnabled ? "enabled" : "disabled") + "', " +
				"'" + (routeInfo.AdminEnabled ? "enabled" : "disabled") + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void AddPopInfo(TICPopInfo popInfo) {
			string tableName = "tic_pops";

			string commandString = "INSERT INTO " + tableName +
				" (id, city, country" +
				", ipv4, ipv6" +
				", heartbeat, tinc, multicast" +
				", ispshort, ispname, ispwebsite" +
				", ispasn, isplir" +
				") VALUES (" +
				"'" + popInfo.POPId + "', " +
				"'" + popInfo.City + "', " +
				"'" + popInfo.Country + "', " +

				"'" + popInfo.IPv4 + "', " +
				"'" + popInfo.IPv6 + "', " +

				"'" + (popInfo.HeartbeatSupport ? "true" : "false") + "', " +
				"'" + (popInfo.TincSupport ? "true" : "false") + "', " +
				"'" + popInfo.MulticastSupport + "', " +

				"'" + popInfo.ISPShort + "', " +
				"'" + popInfo.ISPName + "', " +
				"'" + popInfo.ISPWebsite + "', " +
				popInfo.ISPASNumber + ", " +
				"'" + popInfo.ISPLIRId + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public TICTunnelInfo[] ListTunnels(Int64 userId) {
			if (userId <= 0) {
				return new TICTunnelInfo[] {};
			}

			List<TICTunnelInfo> tunnels = new List<TICTunnelInfo>();

			DataTable dataTable = getDataTable("tic_tunnels", "WHERE ownerid = '" + userId + "'");
			foreach (DataRow dataRow in dataTable.Rows) {
				tunnels.Add(dataRowToTunnelInfo(dataRow));
			}

			return tunnels.ToArray();
		}

		public TICRouteInfo[] ListRoutes(Int64 userId) {
			if (userId <= 0) {
				return new TICRouteInfo[] {};
			}

			List<TICRouteInfo> routes = new List<TICRouteInfo>();

			DataTable dataTable = getDataTable("tic_routes", "WHERE ownerid = '" + userId + "'");
			foreach (DataRow dataRow in dataTable.Rows) {
				routes.Add(dataRowToRouteInfo(dataRow));
			}

			return routes.ToArray();
		}

		public TICPopInfo[] ListPops() {
			List<TICPopInfo> pops = new List<TICPopInfo>();

			DataTable dataTable = getDataTable("tic_pops", null);
			foreach (DataRow dataRow in dataTable.Rows) {
				pops.Add(dataRowToPopInfo(dataRow));
			}

			return pops.ToArray();
		}

		public TICUserInfo GetUserInfo(string userName) {
			if (userName == null) {
				return null;
			}

			DataTable dataTable = getDataTable("tic_users", "WHERE username = '" + userName + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToUserInfo(dataTable.Rows[0]);
		}

		public TICTunnelInfo GetTunnelInfo(Int64 tunnelId) {
			if (tunnelId <= 0) {
				return null;
			}

			DataTable dataTable = getDataTable("tic_tunnels", "WHERE id = '" + tunnelId + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToTunnelInfo(dataTable.Rows[0]);
		}

		public TICRouteInfo GetRouteInfo(Int64 routeId) {
			if (routeId <= 0) {
				return null;
			}

			DataTable dataTable = getDataTable("tic_routes", "WHERE id = '" + routeId + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToRouteInfo(dataTable.Rows[0]);
		}

		public TICPopInfo GetPopInfo(string popId) {
			if (popId == null) {
				return null;
			}

			DataTable dataTable = getDataTable("tic_pops", "WHERE id = '" + popId + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToPopInfo(dataTable.Rows[0]);
		}

		public void UpdateTunnelIPv4Endpoint(Int64 tunnelId, string endpoint) {
			string commandString = "UPDATE tic_tunnels";
			commandString += " SET ipv4endpoint='" + endpoint + "'";
			commandString += " WHERE id=" + tunnelId;

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void UpdateTunnelUserEnabled(Int64 tunnelId, bool enabled) {
			string commandString = "UPDATE tic_tunnels";
			commandString += " SET userstate='" + (enabled ? "enabled" : "disabled") + "'";
			commandString += " WHERE id=" + tunnelId;

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		private DataTable getDataTable(string tableName, string whereString) {
			string commandString = "SELECT * FROM " + tableName;
			if (whereString != null) {
				commandString += " " + whereString;
			}

			DataTable dataTable;
			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;

				DataSet dataSet = new DataSet();
				using (SQLiteDataAdapter adapter = new SQLiteDataAdapter()) {
					adapter.SelectCommand = command;
					adapter.Fill(dataSet, tableName);
				}

				dataTable = dataSet.Tables[tableName];
			}

			return dataTable;
		}

		private TICUserInfo dataRowToUserInfo(DataRow dataRow) {
			TICUserInfo userInfo = new TICUserInfo();
			userInfo.UserId = (Int64) dataRow["id"];

			userInfo.UserName = (string) dataRow["username"];
			userInfo.Password = (string) dataRow["password"];
			userInfo.FullName = (string) dataRow["fullname"];

			return userInfo;
		}

		private TICTunnelInfo dataRowToTunnelInfo(DataRow dataRow) {
			TICTunnelInfo tunnelInfo = new TICTunnelInfo();
			tunnelInfo.TunnelId = (Int64) dataRow["id"];
			tunnelInfo.OwnerId = (Int64) dataRow["ownerid"];

			tunnelInfo.IPv6Endpoint = IPAddress.Parse((string) dataRow["ipv6endpoint"]);
			tunnelInfo.IPv6POP = IPAddress.Parse((string) dataRow["ipv6pop"]);
			tunnelInfo.IPv6PrefixLength = (Int64) dataRow["ipv6prefixlen"];

			tunnelInfo.TunnelMTU = (Int64) dataRow["mtu"];
			tunnelInfo.TunnelName = (string) dataRow["name"];

			tunnelInfo.POPId = (string) dataRow["popid"];
			tunnelInfo.IPv4Endpoint = (string) dataRow["ipv4endpoint"];
			tunnelInfo.IPv4POP = IPAddress.Parse((string) dataRow["ipv4pop"]);

			string userState = (string) dataRow["userstate"];
			tunnelInfo.UserEnabled = userState.Equals("enabled");

			string adminState = (string) dataRow["adminstate"];
			tunnelInfo.AdminEnabled = adminState.Equals("enabled");

			tunnelInfo.Password = (string) dataRow["password"];
			tunnelInfo.HeartbeatInterval = (Int64) dataRow["beatinterval"];

			if (tunnelInfo.IPv4Endpoint.Equals("heartbeat")) {
				tunnelInfo.Type = "6in4-heartbeat";
			} else if (tunnelInfo.IPv4Endpoint.Equals("ayiya")) {
				tunnelInfo.Type = "ayiya";
			} else {
				tunnelInfo.Type = "6in4";
			}

			return tunnelInfo;
		}

		private TICRouteInfo dataRowToRouteInfo(DataRow dataRow) {
			TICRouteInfo routeInfo = new TICRouteInfo();
			routeInfo.RouteId = (Int64) dataRow["id"];
			routeInfo.OwnerId = (Int64) dataRow["ownerid"];
			routeInfo.TunnelId = (Int64) dataRow["tunnelid"];

			routeInfo.IPv6Prefix = IPAddress.Parse((string) dataRow["ipv6prefix"]);
			routeInfo.IPv6PrefixLength = (Int64) dataRow["ipv6prefixlen"];

			routeInfo.Description = (string) dataRow["description"];
			routeInfo.Created = (DateTime) dataRow["created"];
			routeInfo.LastModified = (DateTime) dataRow["lastmodified"];

			string userState = (string) dataRow["userstate"];
			routeInfo.UserEnabled = userState.Equals("enabled");

			string adminState = (string) dataRow["adminstate"];
			routeInfo.AdminEnabled = adminState.Equals("enabled");

			return routeInfo;
		}

		private TICPopInfo dataRowToPopInfo(DataRow dataRow) {
			TICPopInfo popInfo = new TICPopInfo();
			popInfo.POPId = (string) dataRow["id"];
			popInfo.City = (string) dataRow["city"];
			popInfo.Country = (string) dataRow["country"];

			popInfo.IPv4 = IPAddress.Parse((string) dataRow["ipv4"]);
			popInfo.IPv6 = IPAddress.Parse((string) dataRow["ipv6"]);

			popInfo.HeartbeatSupport = (bool) dataRow["heartbeat"];
			popInfo.TincSupport = (bool) dataRow["tinc"];
			popInfo.MulticastSupport = (string) dataRow["multicast"];

			popInfo.ISPShort = (string) dataRow["ispshort"];
			popInfo.ISPName = (string) dataRow["ispname"];
			popInfo.ISPWebsite = (string) dataRow["ispwebsite"];
			popInfo.ISPASNumber = (Int64) dataRow["ispasn"];
			popInfo.ISPLIRId = (string) dataRow["isplir"];

			return popInfo;
		}
	}
}
