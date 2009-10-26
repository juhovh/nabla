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
using System.Threading;

namespace Nabla {
	public class Server {
		private static void Main(string[] args) {
			if (args.Length != 2) {
				Console.WriteLine("Invalid number of arguments\n");
				return;
			}

			SessionManager sessionManager = new SessionManager();
			sessionManager.AddOutputDevice(args[1], true, true);
			sessionManager.AddInputDevice(new TICServer("nabla.db", args[0]));
			sessionManager.AddInputDevice(new TSPServer("nabla.db", args[0]));

			sessionManager.Start();

			while (true) {
				Thread.Sleep(1000);
			}
		}
	}
}
