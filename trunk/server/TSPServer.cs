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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Nabla {
	public class TSPServer {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private TcpListener _tcpListener;
		private Thread _tcpThread;

		/* Use the default port */
		public TSPServer() : this(3653) {}

		public TSPServer(int port) {
			_tcpListener = new TcpListener(IPAddress.Any, port);
			_tcpThread = new Thread(new ThreadStart(listenerThread));
		}

		public void Start() {
			lock (_runlock) {
				_running = true;
				_tcpListener.Start();
				_tcpThread.Start();
			}
		}

		public void Stop() {
			lock (_runlock) {
				_running = false;
				_tcpThread.Join();
				_tcpListener.Stop();
			}
		}

		private void listenerThread() {
			while (_running) {
				TcpClient client = _tcpListener.AcceptTcpClient();

				Thread thread = new Thread(new ParameterizedThreadStart(tcpSessionThread));
				thread.Start(client);
			}
		}

		private void tcpSessionThread(object data) {
			TcpClient client = (TcpClient) data;
			TSPSession session = new TSPSession();

			StreamReader reader = new StreamReader(client.GetStream());
			StreamWriter writer = new StreamWriter(client.GetStream());

			while (!session.Finished()) {
				string line = reader.ReadLine().Trim();

				string response = session.HandleCommand(line);
				writer.Write(response);
				writer.Flush();
			}

			session.Cleanup();
			client.Close();
		}
	}
}
