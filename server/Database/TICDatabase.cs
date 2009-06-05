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
	public class TICDatabase {
		public TICDatabase() {
			SQLiteConnection connection = new SQLiteConnection("Data Source=mydatabase.db");
			connection.Open();

			SQLiteCommand command = new SQLiteCommand(connection);
			command.CommandText = "create table users (id integer primary key autoincrement, username varchar(32), password varchar(128))";
			command.ExecuteNonQuery();
		}
	}
}
