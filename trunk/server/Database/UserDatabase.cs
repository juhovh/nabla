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
	public class UserDatabase : IDisposable {
		private SQLiteConnection _connection;
		private volatile bool _disposed = false;

		public UserDatabase(string dbName) {
			_connection = new SQLiteConnection("Data Source=" + dbName);
			_connection.Open();
		}

		public void CreateTables() {
			string userString = "CREATE TABLE users (" +
				"id integer primary key autoincrement" +
				", enabled boolean" +
				", username varchar(32)" +
				", password varchar(64)" +
				", tunnel_password varchar(128)" +
				", fullname varchar(128))";
			string tunnelString = "CREATE TABLE tunnels (" +
				"id integer primary key autoincrement" +
				", ownerid integer" + 
				", created datetime" +
				", lastmodified datetime" +
				", enabled boolean" +

				", name varchar(128)" + 
				", type varchar(32)" +
				", endpoint varchar(39)" +
				", userenabled boolean" +
				", password varchar(32))";
			string routeString = "CREATE TABLE routes (" +
				"id integer primary key autoincrement" +
				", ownerid integer" + 
				", tunnelid integer" +
				", created datetime" +
				", lastmodified datetime" +
				", enabled boolean" +

				", description varchar(512)" +
				", userenabled boolean)";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = userString;
				command.ExecuteNonQuery();
				command.CommandText = tunnelString;
				command.ExecuteNonQuery();
				command.CommandText = routeString;
				command.ExecuteNonQuery();
			}
		}

		public void AddUserInfo(UserInfo userInfo) {
			string passwordHash = SHA256WithSalt(userInfo.Password, null);

			string commandString = "INSERT INTO users " +
				" (enabled, username, password, tunnel_password, fullname) VALUES (" +
				"'" + (userInfo.Enabled ? 1 : 0) + "', " +
				"'" + userInfo.UserName + "', " +
				"'" + passwordHash + "', " +
				"'" + userInfo.TunnelPassword + "', " +
				"'" + userInfo.FullName + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public bool ValidatePassword(string userName, string password) {
			if (userName == null || password == null) {
				return false;
			}

			DataTable dataTable = getDataTable("users", "WHERE username='" + userName + "'");
			if (dataTable.Rows.Count == 0) {
				return false;
			}

			string ourHash = (string) dataTable.Rows[0]["password"];
			string salt = ourHash.Substring(0, ourHash.IndexOf("$"));
			byte[] saltBytes = Convert.FromBase64String(salt);
			string theirHash = SHA256WithSalt(password, saltBytes);

			return ourHash.Equals(theirHash);
		}

		public UserInfo[] ListUsers() {
			List<UserInfo> users = new List<UserInfo>();

			DataTable dataTable = getDataTable("users", null);
			foreach (DataRow dataRow in dataTable.Rows) {
				users.Add(dataRowToUserInfo(dataRow));
			}

			return users.ToArray();
		}

		public UserInfo GetUserInfo(string userName) {
			if (userName == null) {
				return null;
			}

			DataTable dataTable = getDataTable("users", "WHERE username='" + userName + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToUserInfo(dataTable.Rows[0]);
		}

		private UserInfo dataRowToUserInfo(DataRow dataRow) {
			UserInfo userInfo = new UserInfo();
			userInfo.UserId = (Int64) dataRow["id"];
			userInfo.Enabled = (bool) dataRow["enabled"];

			userInfo.UserName = (string) dataRow["username"];
			userInfo.Password = "";
			userInfo.TunnelPassword = (string) dataRow["tunnel_password"];
			userInfo.FullName = (string) dataRow["fullname"];

			return userInfo;
		}





		public void AddTunnelInfo(TunnelInfo tunnelInfo) {
			tunnelInfo.Created = DateTime.UtcNow;
			tunnelInfo.LastModified = DateTime.UtcNow;

			string commandString = "INSERT INTO tunnels " +
				" (ownerid, created, lastmodified, enabled, " +
				"  name, type, endpoint, userenabled, password) VALUES (" +
				"'" + tunnelInfo.OwnerId + "', " +
				"datetime('" + tunnelInfo.Created.ToString("s") + "'), " +
				"datetime('" + tunnelInfo.LastModified.ToString("s") + "'), " +
				"'" + (tunnelInfo.Enabled ? 1 : 0) + "', " +

				"'" + tunnelInfo.Name + "', " +
				"'" + tunnelInfo.Type + "', " +
				"'" + tunnelInfo.Endpoint + "', " +
				"'" + (tunnelInfo.UserEnabled ? 1 : 0) + "', " +
				"'" + tunnelInfo.Password + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void UpdateTunnelEndpoint(Int64 tunnelId, string endpoint) {
			string commandString = "UPDATE tunnels SET endpoint='" + endpoint + "'" +
			                       " WHERE id=" + tunnelId;

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public void UpdateTunnelUserEnabled(Int64 tunnelId, bool enabled) {
			string commandString = "UPDATE tunnels SET userenabled='" + (enabled ? 1 : 0) + "'" +
			                       " WHERE id=" + tunnelId;

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public TunnelInfo[] ListTunnels(Int64 userId) {
			return ListTunnels(userId, null);
		}

		public TunnelInfo[] ListTunnels(string type) {
			return ListTunnels(0, type);
		}

		public TunnelInfo[] ListTunnels(Int64 userId, string type) {
			if (userId <= 0 && type == null) {
				return new TunnelInfo[] {};
			}

			List<TunnelInfo> tunnels = new List<TunnelInfo>();
			string whereString = "WHERE";
			if (userId > 0) {
				whereString += " ownerid=" + userId;
			}
			if (type != null) {
				if (userId > 0) {
					whereString += " AND";
				}

				whereString += " type='" + type + "'";
			}

			DataTable dataTable = getDataTable("tunnels", whereString);
			foreach (DataRow dataRow in dataTable.Rows) {
				tunnels.Add(dataRowToTunnelInfo(dataRow));
			}

			return tunnels.ToArray();
		}

		public TunnelInfo GetTunnelInfo(Int64 tunnelId) {
			if (tunnelId <= 0) {
				return null;
			}

			DataTable dataTable = getDataTable("tunnels", "WHERE id=" + tunnelId);
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToTunnelInfo(dataTable.Rows[0]);
		}

		private TunnelInfo dataRowToTunnelInfo(DataRow dataRow) {
			TunnelInfo tunnelInfo = new TunnelInfo();
			tunnelInfo.TunnelId = (Int64) dataRow["id"];
			tunnelInfo.OwnerId = (Int64) dataRow["ownerid"];
			tunnelInfo.Created = (DateTime) dataRow["created"];
			tunnelInfo.LastModified = (DateTime) dataRow["lastmodified"];
			tunnelInfo.Enabled = (bool) dataRow["enabled"];

			tunnelInfo.Name = (string) dataRow["name"];
			tunnelInfo.Type = (string) dataRow["type"];
			tunnelInfo.Endpoint = (string) dataRow["endpoint"];
			tunnelInfo.UserEnabled = (bool) dataRow["userenabled"];
			tunnelInfo.Password = (string) dataRow["password"];

			return tunnelInfo;
		}





		public void AddRouteInfo(RouteInfo routeInfo) {
			routeInfo.Created = DateTime.UtcNow;
			routeInfo.LastModified = DateTime.UtcNow;

			string commandString = "INSERT INTO routes " +
				" (tunnelid, ownerid, created, lastmodified, enabled, description, userenabled) VALUES (" +
				"'" + routeInfo.TunnelId + "', " +
				"'" + routeInfo.OwnerId + "', " +
				"datetime('" + routeInfo.Created.ToString("s") + "'), " +
				"datetime('" + routeInfo.LastModified.ToString("s") + "'), " +
				"'" + (routeInfo.Enabled ? 1 : 0) + "', " +

				"'" + routeInfo.Description + "', " +
				"'" + (routeInfo.UserEnabled ? 1 : 0) + "')";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = commandString;
				command.ExecuteNonQuery();
			}
		}

		public RouteInfo[] ListRoutes(Int64 userId) {
			if (userId <= 0) {
				return new RouteInfo[] {};
			}

			List<RouteInfo> routes = new List<RouteInfo>();

			DataTable dataTable = getDataTable("routes", "WHERE ownerid=" + userId);
			foreach (DataRow dataRow in dataTable.Rows) {
				routes.Add(dataRowToRouteInfo(dataRow));
			}

			return routes.ToArray();
		}

		public RouteInfo GetRouteInfo(Int64 routeId) {
			if (routeId <= 0) {
				return null;
			}

			DataTable dataTable = getDataTable("routes", "WHERE id=" + routeId);
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToRouteInfo(dataTable.Rows[0]);
		}

		private RouteInfo dataRowToRouteInfo(DataRow dataRow) {
			RouteInfo routeInfo = new RouteInfo();
			routeInfo.RouteId = (Int64) dataRow["id"];
			routeInfo.OwnerId = (Int64) dataRow["ownerid"];
			routeInfo.TunnelId = (Int64) dataRow["tunnelid"];
			routeInfo.Created = (DateTime) dataRow["created"];
			routeInfo.LastModified = (DateTime) dataRow["lastmodified"];
			routeInfo.Enabled = (bool) dataRow["enabled"];

			routeInfo.Description = (string) dataRow["description"];
			routeInfo.UserEnabled = (bool) dataRow["userenabled"];

			return routeInfo;
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

		private string SHA256WithSalt(string key, byte[] saltBytes) {
			byte[] keyBytes = Encoding.UTF8.GetBytes(key);

			if (saltBytes == null) {
				/* Randomize the salt size */
				Random rand = new Random();
				saltBytes = new byte[rand.Next(4, 9)];

				/* Fill salt with random bytes */
				RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
				rng.GetNonZeroBytes(saltBytes);
			}

			byte[] bytes = new byte[keyBytes.Length + saltBytes.Length];
			Array.Copy(keyBytes, 0, bytes, 0, keyBytes.Length);
			Array.Copy(saltBytes, 0, bytes, keyBytes.Length, saltBytes.Length);

			HashAlgorithm hash = new SHA256Managed();
			byte[] hashBytes = hash.ComputeHash(bytes);

			string ret = "";
			ret += Convert.ToBase64String(saltBytes) + "$";
			ret += Convert.ToBase64String(hashBytes);
			return ret;
		}

		public void Dispose() {
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		private void Dispose(bool disposing) {
			if (_disposed) {
				return;
			}

			/* If true, method is called from user code */
			if (disposing) {
				/* Dispose managed resources. */
				_connection.Close();
				_connection.Dispose();
			}

			_disposed = true;
		}
	}
}
