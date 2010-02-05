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
using System.Collections.Generic;

namespace Nabla {
	public class TSPServer : InputDevice {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private string _dbName;
		private string _deviceName;
		private Socket _udpSocket;
		private TcpListener _tcpListener;
		private SessionManager _sessionManager;
		private Thread _udpThread;
		private Thread _tcpThread;

		private Dictionary<IPEndPoint, TSPSession> _udpSessions =
			new Dictionary<IPEndPoint, TSPSession>();

		/* Use the default port */
		public TSPServer(string dbName, string deviceName) : this(dbName, deviceName, 3653) {}

		public TSPServer(string dbName, string deviceName, int port) {
			_dbName = dbName;
			_deviceName = deviceName;

			_udpSocket = new Socket(AddressFamily.InterNetworkV6,
			                        SocketType.Dgram,
			                        ProtocolType.Udp);
			_udpSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
			_tcpListener = new TcpListener(IPAddress.Any, port);
		}

		public override void SetSessionManager(SessionManager sessionManager) {
			InputDevice dev;
			dev = new GenericInputDevice(_deviceName, GenericInputType.IPv6inIPv4);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(_deviceName, GenericInputType.IPv4inIPv6);
			sessionManager.AddInputDevice(dev);

			_sessionManager = sessionManager;
		}

		public override TunnelType[] GetSupportedTypes() {
			/* We will handle IPv6inUDP ourselves */
			return new TunnelType[] { TunnelType.IPv6inUDP };
		}

		public override void Start() {
			lock (_runlock) {
				_tcpListener.Start();
				_running = true;

				_udpThread = new Thread(new ThreadStart(udpListenerThread));
				_udpThread.Start();
				_tcpThread = new Thread(new ThreadStart(tcpListenerThread));
				_tcpThread.Start();
			}
		}

		public override void Stop() {
			lock (_runlock) {
				_running = false;
				_tcpThread.Join();
				_tcpListener.Stop();
			}
		}

		public override void SendPacket(TunnelSession session, byte[] data) {
			/* XXX: Handle IPv6inUDP incoming data */
		}

		private void udpListenerThread() {
			byte[] data = new byte[2048];

			while (_running) {
				EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.IPv6Any, 0);

				int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
				                                     SocketFlags.None,
				                                     ref sender);
				Console.WriteLine("Received TSP packet from {0}", sender);

				IPEndPoint endPoint = InputDevice.GetIPEndPoint(sender);
				IPEndPoint localEndPoint = (IPEndPoint) _udpSocket.LocalEndPoint;
				Console.WriteLine("Local end point address: " + localEndPoint.Address);

				if (!_udpSessions.ContainsKey(endPoint)) {
					TSPSession s = new TSPSession(_sessionManager, _dbName,
					                              ProtocolType.Udp,
					                              endPoint.Address,
					                              localEndPoint.Address);
					_udpSessions.Add(endPoint, s);
				}

				Console.WriteLine("Contents of UDP packet: ");
				byte[] tspData = new byte[datalen-8];
				Array.Copy(data, 8, tspData, 0, tspData.Length);

				string tspString = Encoding.UTF8.GetString(tspData);
				if (tspString.StartsWith("Content-length:")) {
					int newline = tspString.IndexOf("\r\n");
					if (newline < 0) {
						Console.WriteLine("Invalid packet, no newline after Content-length");
						continue;
					}

					string firstline = tspString.Substring(0, newline);
					string lenstr = firstline.Substring("Content-length:".Length).Trim();
					try {
						int len = int.Parse(lenstr);

						byte[] content = new byte[len];
						Array.Copy(tspData, newline+2, content, 0, len);
						tspData = content;
					} catch (Exception e) {
						Console.WriteLine("Exception parsing Content-length: " + e);
					}
				}
				Console.WriteLine(Encoding.UTF8.GetString(tspData));

				TSPSession session = _udpSessions[endPoint];
				string line = Encoding.UTF8.GetString(tspData);

				string[] responses = session.HandleCommand(line);
				if (responses == null)
					continue;

				/* XXX: Multiple responses should be queued for seq numbers */
				foreach (string r in responses) {
					tspData = Encoding.UTF8.GetBytes(r);
					Array.Copy(tspData, 0, data, 8, tspData.Length);
					_udpSocket.SendTo(data, tspData.Length+8,
					                  SocketFlags.None, endPoint);
				}
			}
		}

		private void tcpListenerThread() {
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

			IPEndPoint remoteEndPoint = InputDevice.GetIPEndPoint(client.Client.RemoteEndPoint);
			IPEndPoint localEndPoint = InputDevice.GetIPEndPoint(client.Client.LocalEndPoint);
			TSPSession session = new TSPSession(_sessionManager, _dbName, ProtocolType.Tcp,
			                                    remoteEndPoint.Address, localEndPoint.Address);

			Stream stream = client.GetStream();

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

				/* Content-length of response depends on the state before the command */
				bool outputContentLength = session.OutputContentLength;
				string[] responses = session.HandleCommand(line);
				if (responses == null)
					continue;

				foreach (string response in responses) {
					byte[] outBytes = Encoding.UTF8.GetBytes(response);
					if (outputContentLength) {
						string clString = "Content-length: " + outBytes.Length + "\r\n";
						byte[] clBytes = Encoding.UTF8.GetBytes(clString);

						byte[] tmpBytes = new byte[clBytes.Length + outBytes.Length];
						Array.Copy(clBytes, 0, tmpBytes, 0, clBytes.Length);
						Array.Copy(outBytes, 0, tmpBytes, clBytes.Length, outBytes.Length);
						outBytes = tmpBytes;
					}
					stream.Write(outBytes, 0, outBytes.Length);
					stream.Flush();
				}
			}

			session.Cleanup();
			client.Close();
		}
	}
}
