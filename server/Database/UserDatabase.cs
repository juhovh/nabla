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
	public class UserDatabase {
		private SQLiteConnection _connection;

		public UserDatabase(string dbName) {
			_connection = new SQLiteConnection("Data Source=" + dbName);
			_connection.Open();
		}

		public void Cleanup() {
			_connection.Close();
			_connection.Dispose();
		}

		public void CreateTables() {
			string userString = "CREATE TABLE users (" +
				"id integer primary key autoincrement" +
				", username varchar(32)" +
				", password varchar(64)" +
				", tunnelpw varchar(32)" +
				", fullname varchar(128))";

			using (SQLiteCommand command = new SQLiteCommand(_connection)) {
				command.CommandText = userString;
				command.ExecuteNonQuery();
			}
		}

		public void AddUserInfo(UserInfo userInfo) {
			string tableName = "users";

			string passwordHash = SHA256WithSalt(userInfo.Password, null);

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] pwBytes = Encoding.UTF8.GetBytes(userInfo.TunnelPassword);
			byte[] pwHashBytes = md5.ComputeHash(pwBytes);
			string tunnelPasswordHash = BitConverter.ToString(pwHashBytes).Replace("-", "").ToLower();

			string commandString = "INSERT INTO " + tableName +
				" (username, password, tunnelpw, fullname) VALUES (" +
				"'" + userInfo.UserName + "', " +
				"'" + passwordHash + "', " +
				"'" + tunnelPasswordHash + "', " +
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

			DataTable dataTable = getDataTable("users", "WHERE username = '" + userName + "'");
			if (dataTable.Rows.Count == 0) {
				return false;
			}

			string ourHash = (string) dataTable.Rows[0]["password"];
			string salt = ourHash.Substring(0, ourHash.IndexOf("$"));
			byte[] saltBytes = Convert.FromBase64String(salt);
			string theirHash = SHA256WithSalt(password, saltBytes);

			return ourHash.Equals(theirHash);
		}

		public UserInfo GetUserInfo(string userName) {
			if (userName == null) {
				return null;
			}

			DataTable dataTable = getDataTable("users", "WHERE username = '" + userName + "'");
			if (dataTable.Rows.Count == 0) {
				return null;
			}

			return dataRowToUserInfo(dataTable.Rows[0]);
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

		private UserInfo dataRowToUserInfo(DataRow dataRow) {
			UserInfo userInfo = new UserInfo();
			userInfo.UserId = (Int64) dataRow["id"];

			userInfo.UserName = (string) dataRow["username"];
			userInfo.Password = "";
			userInfo.TunnelPassword = (string) dataRow["tunnelpw"];
			userInfo.FullName = (string) dataRow["fullname"];

			return userInfo;
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
	}
}
