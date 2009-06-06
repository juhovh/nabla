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

	public class TICDatabase : IDisposable {
		SQLiteConnection _conn;

		public TICDatabase(string filename) {
			_conn = new SQLiteConnection("Data Source=" + filename);
			_conn.Open();
		}

		public void CreateTables() {
			using (SQLiteCommand command = new SQLiteCommand(_conn)) {
				command.CommandText = "CREATE TABLE tic_users (id integer primary key autoincrement, username varchar(32), password varchar(32), fullname varchar(128))";
				command.ExecuteNonQuery();
			}
		}

		public TICUserInfo GetUserInfo(string userName) {
			string tableName = "tic_users";
			TICUserInfo userInfo = null;

			if (userName == null) {
				userName = "*";
			}

			using (SQLiteCommand command = new SQLiteCommand(_conn)) {
				command.CommandText = "SELECT * FROM " + tableName + " WHERE username = " + userName;

				SQLiteDataAdapter adapter = new SQLiteDataAdapter();
				adapter.SelectCommand = command;

				DataSet dataSet = new DataSet();
				adapter.Fill(dataSet, tableName);

				foreach (DataRow dataRow in dataSet.Tables[tableName].Rows) {
					userInfo = new TICUserInfo();
					userInfo.UserName = dataRow["username"].ToString();
					userInfo.Password = dataRow["password"].ToString();
					userInfo.FullName = dataRow["fullname"].ToString();
				}
			}

			return userInfo;
		}

		public void Dispose() {
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing) {
			if (disposing) {
				_conn.Close();
				_conn.Dispose();
			}
		}
	}
}
