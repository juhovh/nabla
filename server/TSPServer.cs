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
using System.Text;
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
			byte[] buf = new byte[512];
			int buflen = 0;

			TcpClient client = (TcpClient) data;
			TSPSession session = new TSPSession();

			Stream stream = client.GetStream();
			StreamWriter writer = new StreamWriter(client.GetStream());

			while (!session.Finished()) {
				int read = stream.Read(buf, buflen, buf.Length-buflen);
				if (read == 0 && buflen == 0) {
					/* XXX: End of file */
					break;
				}
				buflen += read;

				/* Find a newline in buffer */
				int newline = -1;
				for (int i=1; i<buflen; i++) {
					if (buf[i] == '\n' && buf[i-1] == '\r') {
						newline = i-1;
						break;
					}
				}

				if (newline == -1) {
					/* XXX: No newline found */
					break;
				}

				string line = Encoding.UTF8.GetString(buf, 0, newline);

				/* Move the additional bytes to the beginning of buffer */
				buflen -= newline+2;
				Array.Copy(buf, newline+2, buf, 0, buflen);

				/* This is weird, why is there sometimes nulls? */
				while (line[0] == '\0') {
					line = line.Substring(1);
				}

				/* If Content-length is set, read multiline content */
				if (line.StartsWith("Content-length:")) {
					string lenstr = line.Substring("Content-length:".Length).Trim();
					try {
						int len = int.Parse(lenstr);
						byte[] content = new byte[len];

						while (buflen < content.Length) {
							read = stream.Read(buf, buflen, buf.Length-buflen);
							if (read == 0) {
								break;
							}
							buflen += read;
						}

						if (buflen < content.Length) {
							/* XXX: End of file */
							break;
						}

						/* Copy content into the content array */
						Array.Copy(buf, 0, content, 0, content.Length);

						/* Move the additional bytes to the beginning of buffer */
						buflen -= content.Length;
						Array.Copy(buf, content.Length, buf, 0, buflen);

						line = Encoding.UTF8.GetString(content);
					} catch (Exception) {
						/* XXX: Break doesn't work here very well */
						break;
					}
				}

				string response = session.HandleCommand(line);
				writer.Write(response);
				writer.Flush();
			}

			session.Cleanup();
			client.Close();
		}
	}
}
