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
using System.Security.Cryptography;

namespace Nabla.Database {
	public class TICDatabase {
		string _dbName;

		public TICDatabase(string dbName) {
			_dbName = dbName;
		}

		public void CreateTables() {
			string connectionString = "Data Source=" + _dbName;
			string userString = "CREATE TABLE tic_users (" +
				"id integer primary key autoincrement" +
				", username varchar(32)" +
				", password varchar(32)" +
				", fullname varchar(128))";
			string tunnelString = "CREATE TABLE tic_tunnels (" +
				"id integer primary key autoincrement" +
				", ipv6endpoint varchar(39)" +
				", ipv6pop varchar(39)" +
				", ipv6prefixlen integer" +
				", mtu integer" +
				", name varchar(64)" +
				", popid varchar(8)" +
				", ipv4endpoint varchar(15)" +
				", ipv4pop varchar(15)" +
				", userenabled boolean" +
				", adminenabled boolean" +
				", password varchar(32)" +
				", beatinterval integer)";
			string routeString = "CREATE TABLE tic_routes (" +
				"id integer primary key autoincrement" +
				", ipv6prefix varchar(39)" +
				", ipv6prefixlen integer" +
				", description varchar(512)" +
				", created varchar(19)" +
				", lastmodified varchar(19)" +
				", userenabled boolean" +
				", adminenabled boolean)";
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

			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) { 
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = userString;
					command.ExecuteNonQuery();
					command.CommandText = tunnelString;
					command.ExecuteNonQuery();
					command.CommandText = routeString;
					command.ExecuteNonQuery();
					command.CommandText = popString;
					command.ExecuteNonQuery();
				}
				connection.Close();
			}
		}

		public void AddUserInfo(TICUserInfo userInfo) {
			string tableName = "tic_users";

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] pwBytes = Encoding.UTF8.GetBytes(userInfo.Password);
			byte[] pwHashBytes = md5.ComputeHash(pwBytes);
			string pwHash = BitConverter.ToString(pwHashBytes).Replace("-", "").ToLower();

			string connectionString = "Data Source=" + _dbName;
			string commandString = "INSERT INTO " + tableName +
				" (username, password, fullname) VALUES (" +
				"'" + userInfo.UserName + "', " +
				"'" + pwHash + "', " +
				"'" + userInfo.FullName + "')";

			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) { 
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;
					command.ExecuteNonQuery();
				}
				connection.Close();
			}
		}

		public void AddTunnelInfo(TICTunnelInfo tunnelInfo) {
			string tableName = "tic_tunnels";

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] pwBytes = Encoding.UTF8.GetBytes(tunnelInfo.Password);
			byte[] pwHashBytes = md5.ComputeHash(pwBytes);
			string pwHash = BitConverter.ToString(pwHashBytes).Replace("-", "").ToLower();

			string connectionString = "Data Source=" + _dbName;
			string commandString = "INSERT INTO " + tableName +
				" (ipv6endpoint, ipv6pop, ipv6prefixlen" +
				", mtu, name, popid" +
				", ipv4endpoint, ipv4pop" +
				", userenabled, adminenabled" +
				", password, beatinterval" +
				") VALUES (" +
				"'" + tunnelInfo.IPv6EndPoint + "', " +
				"'" + tunnelInfo.IPv6POP + "', " +
				tunnelInfo.IPv6PrefixLength + ", " +

				tunnelInfo.TunnelMTU + ", " +
				"'" + tunnelInfo.TunnelName + "', " +

				"'" + tunnelInfo.POPId + "', " +
				"'" + tunnelInfo.IPv4Endpoint + "', " +
				"'" + tunnelInfo.IPv4POP + "', " +

				"'" + (tunnelInfo.UserEnabled ? "true" : "false") + "', " +
				"'" + (tunnelInfo.AdminEnabled ? "true" : "false") + "', " +

				"'" + pwHash + "', " +
				tunnelInfo.HeartbeatInterval + ")";

			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) { 
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;
					command.ExecuteNonQuery();
				}
				connection.Close();
			}
		}

		public void AddRouteInfo(TICRouteInfo routeInfo) {
			string tableName = "tic_routes";

			routeInfo.Created = DateTime.UtcNow;
			routeInfo.LastModified = DateTime.UtcNow;

			string connectionString = "Data Source=" + _dbName;
			string commandString = "INSERT INTO " + tableName +
				" (ipv6prefix, ipv6prefixlen" +
				", description" +
				", crated, lastmodified" +
				", userenabled, adminenabled" +
				") VALUES (" +
				"'" + routeInfo.IPv6Prefix + "', " +
				routeInfo.IPv6PrefixLength + ", " +

				"'" + routeInfo.Description + ", " +

				"'" + routeInfo.Created.ToString("s") + "', " +
				"'" + routeInfo.LastModified.ToString("s") + "', " +

				"'" + (routeInfo.UserEnabled ? "true" : "false") + "', " +
				"'" + (routeInfo.AdminEnabled ? "true" : "false") + "')";

			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) { 
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;
					command.ExecuteNonQuery();
				}
				connection.Close();
			}
		}

		public void AddPopInfo(TICPopInfo popInfo) {
			string tableName = "tic_pops";

			string connectionString = "Data Source=" + _dbName;
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

			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) { 
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;
					command.ExecuteNonQuery();
				}
				connection.Close();
			}
		}

		public TICUserInfo GetUserInfo(string userName) {
			string tableName = "tic_users";

			string connectionString = "Data Source=" + _dbName;
			string commandString = "SELECT * FROM " + tableName;
			if (userName != null) {
				commandString += " WHERE username = '" + userName + "'";
			}

			TICUserInfo userInfo = null;
			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) {
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;

					DataSet dataSet = new DataSet();
					using (SQLiteDataAdapter adapter = new SQLiteDataAdapter()) {
						adapter.SelectCommand = command;
						adapter.Fill(dataSet, tableName);
					}

					foreach (DataRow dataRow in dataSet.Tables[tableName].Rows) {
						userInfo = new TICUserInfo();
						userInfo.UserName = dataRow["username"].ToString();
						userInfo.Password = dataRow["password"].ToString();
						userInfo.FullName = dataRow["fullname"].ToString();
					}
				}
				connection.Close();
			}

			return userInfo;
		}

		public TICTunnelInfo GetTunnelInfo(int tunnelId) {
			string tableName = "tic_tunnels";
			if (tunnelId <= 0) {
				return null;
			}

			string connectionString = "Data Source=" + _dbName;
			string commandString = "SELECT * FROM " + tableName + " WHERE id = " + tunnelId;

			TICTunnelInfo tunnelInfo = null;
			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) {
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;

					DataSet dataSet = new DataSet();
					using (SQLiteDataAdapter adapter = new SQLiteDataAdapter()) {
						adapter.SelectCommand = command;
						adapter.Fill(dataSet, tableName);
					}

					foreach (DataRow dataRow in dataSet.Tables[tableName].Rows) {
						tunnelInfo = new TICTunnelInfo();
						tunnelInfo.TunnelId = (Int64) dataRow["id"];

						tunnelInfo.IPv6EndPoint = IPAddress.Parse((string) dataRow["ipv6endpoint"]);
						tunnelInfo.IPv6POP = IPAddress.Parse((string) dataRow["ipv6pop"]);
						tunnelInfo.IPv6PrefixLength = (Int64) dataRow["ipv6prefixlen"];

						tunnelInfo.TunnelMTU = (Int64) dataRow["mtu"];
						tunnelInfo.TunnelName = (string) dataRow["name"];

						tunnelInfo.POPId = (string) dataRow["popid"];
						tunnelInfo.IPv4Endpoint = (string) dataRow["ipv4endpoint"];
						tunnelInfo.IPv4POP = IPAddress.Parse((string) dataRow["ipv4pop"]);

						tunnelInfo.UserEnabled = (bool) dataRow["userenabled"];
						tunnelInfo.AdminEnabled = (bool) dataRow["adminenabled"];

						tunnelInfo.Password = (string) dataRow["password"];
						tunnelInfo.HeartbeatInterval = (Int64) dataRow["beatinterval"];

						if (tunnelInfo.IPv4Endpoint.Equals("heartbeat")) {
							tunnelInfo.Type = "6in4-heartbeat";
						} else if (tunnelInfo.IPv4Endpoint.Equals("ayiya")) {
							tunnelInfo.Type = "ayiya";
						} else {
							tunnelInfo.Type = "6in4";
						}
					}
				}
				connection.Close();
			}

			return tunnelInfo;
		}

		public TICRouteInfo GetRouteInfo(int routeId) {
			string tableName = "tic_routes";
			if (routeId <= 0) {
				return null;
			}

			string connectionString = "Data Source=" + _dbName;
			string commandString = "SELECT * FROM " + tableName + " WHERE id = " + routeId;

			TICRouteInfo routeInfo = null;
			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) {
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;

					DataSet dataSet = new DataSet();
					using (SQLiteDataAdapter adapter = new SQLiteDataAdapter()) {
						adapter.SelectCommand = command;
						adapter.Fill(dataSet, tableName);
					}

					foreach (DataRow dataRow in dataSet.Tables[tableName].Rows) {
						System.Globalization.CultureInfo provider
							= System.Globalization.CultureInfo.InvariantCulture;

						routeInfo = new TICRouteInfo();
						routeInfo.RouteId = (Int64) dataRow["id"];

						routeInfo.IPv6Prefix = IPAddress.Parse((string) dataRow["ipv6prefix"]);
						routeInfo.IPv6PrefixLength = (Int64) dataRow["ipv6prefixlen"];

						routeInfo.Description = (string) dataRow["description"];
						routeInfo.Created = DateTime.ParseExact((string) dataRow["created"], "s", provider);
						routeInfo.LastModified = DateTime.ParseExact((string) dataRow["lastmodified"], "s", provider);

						routeInfo.UserEnabled = (bool) dataRow["userenabled"];
						routeInfo.AdminEnabled = (bool) dataRow["adminenabled"];
					}
				}
				connection.Close();
			}

			return routeInfo;
		}

		public TICPopInfo GetPopInfo(string popId) {
			string tableName = "tic_pops";
			if (popId == null) {
				return null;
			}

			string connectionString = "Data Source=" + _dbName;
			string commandString = "SELECT * FROM " + tableName + " WHERE id = '" + popId + "'";

			TICPopInfo popInfo = null;
			using (SQLiteConnection connection = new SQLiteConnection(connectionString)) {
				connection.Open();
				using (SQLiteCommand command = new SQLiteCommand(connection)) {
					command.CommandText = commandString;

					DataSet dataSet = new DataSet();
					using (SQLiteDataAdapter adapter = new SQLiteDataAdapter()) {
						adapter.SelectCommand = command;
						adapter.Fill(dataSet, tableName);
					}

					foreach (DataRow dataRow in dataSet.Tables[tableName].Rows) {
						popInfo = new TICPopInfo();
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
					}
				}
				connection.Close();
			}

			return popInfo;
		}
	}
}
