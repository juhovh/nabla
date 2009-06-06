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
using System.Data;
using System.Data.SQLite;

namespace Nabla.Database {
	public class TICUserInfo {
		public string UserName;
		public string Password;
		public string FullName;
	}

	public class TICDatabase {
		string _dbName;

		public TICDatabase(string dbName) {
			_dbName = dbName;
		}

		public void CreateTables() {
			string connectionString = "Data Source=" + _dbName;
			string commandString = "CREATE TABLE tic_users (" +
				"id integer primary key autoincrement" +
				", username varchar(32)" +
				", password varchar(32)" +
				", fullname varchar(128))";

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
	}
}
