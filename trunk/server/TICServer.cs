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
using System.Net.Sockets;
using System.Threading;

namespace Nabla {
	public class TICServer {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private TcpListener _listener;
		private Thread _thread;

		/* Use the default port */
		public TICServer() : this(3874) {}

		public TICServer(int port) {
			_listener = new TcpListener(IPAddress.Any, port);
			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start() {
			lock (_runlock) {
				_running = true;
				_listener.Start();
				_thread.Start();
			}
		}

		public void Stop() {
			lock (_runlock) {
				_running = false;
				_thread.Join();
				_listener.Stop();
			}
		}

		private void threadLoop() {
			while (_running) {
				TcpClient client = _listener.AcceptTcpClient();
				TICSession session = new TICSession(client, "Nabla", "http://code.google.com/p/nabla/");
				session.Start();
			}
		}
	}
}
