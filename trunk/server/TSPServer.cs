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
using Nabla.Sockets;

namespace Nabla {
	public class TSPServer : InputDevice {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private string _dbName;
		private string _deviceName;
		private bool _ipv6;

		private Socket _udpSocket;
		private TcpListener _tcpListener;
		private SessionManager _sessionManager;
		private Thread _udpThread;
		private Thread _tcpThread;

		private Dictionary<IPEndPoint, TSPSession> _udpSessions =
			new Dictionary<IPEndPoint, TSPSession>();

		/* Use the default port */
		public TSPServer(string dbName, string deviceName, bool ipv6) : this(dbName, deviceName, ipv6, 3653) {}

		public TSPServer(string dbName, string deviceName, bool ipv6, int port) {
			_dbName = dbName;
			_deviceName = deviceName;
			_ipv6 = ipv6;

			IPAddress bindAddr = null;
			Dictionary<IPAddress, IPAddress> addrs = RawSocket.GetIPAddresses(deviceName);
			if (ipv6) {
				foreach (IPAddress addr in addrs.Keys) {
					if (addr.AddressFamily == AddressFamily.InterNetworkV6 && !addr.IsIPv6LinkLocal) {
						bindAddr = addr;
						break;
					}
				}
			} else {
				foreach (IPAddress addr in addrs.Keys) {
					if (addr.AddressFamily == AddressFamily.InterNetwork) {
						bindAddr = addr;
						break;
					}
				}
			}
			if (bindAddr == null) {
				throw new Exception("Couldn't find an address to bind TSP service to");
			}
			
			_udpSocket = new Socket(AddressFamily.InterNetwork,
			                        SocketType.Dgram,
			                        ProtocolType.Udp);
			_udpSocket.Bind(new IPEndPoint(bindAddr, port));
			_tcpListener = new TcpListener(bindAddr, port);
		}

		public override void SetSessionManager(SessionManager sessionManager) {
			InputDevice dev;
			if (_ipv6) {
				dev = new GenericInputDevice(_deviceName, TunnelType.IPv4inIPv6);
				sessionManager.AddInputDevice(dev);
			} else {
				dev = new GenericInputDevice(_deviceName, TunnelType.IPv6inIPv4);
				sessionManager.AddInputDevice(dev);
			}

			_sessionManager = sessionManager;
		}

		public override TunnelType[] GetSupportedTypes() {
			if (!_ipv6) {
				/* We will handle IPv6inUDP ourselves */
				return new TunnelType[] { TunnelType.IPv6inUDP };
			} else {
				return new TunnelType[] {};
			}
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

		public override void SendPacket(Int64 tunnelId, byte[] data) {
			IPEndPoint endPoint = _sessionManager.GetSessionEndPoint(tunnelId);

			TSPSession tspSession = null;
			if (_udpSessions.ContainsKey(endPoint)) {
				tspSession = _udpSessions[endPoint];
			}

			// XXX: Should check that tunnel type is v6udpv4
			_udpSocket.SendTo(data, endPoint);
		}

		private void udpListenerThread() {
			byte[] data = new byte[2048];

			while (_running) {
				EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.IPv6Any, 0);

				int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
				                                     SocketFlags.None,
				                                     ref sender);

				/* Too small packets are ignored */
				if (datalen < 8)
					continue;

				IPEndPoint endPoint = InputDevice.GetIPEndPoint(sender);
				IPEndPoint localEndPoint = (IPEndPoint) _udpSocket.LocalEndPoint;

				/* If the protocol version is 0xf, packet is a signaling packet */
				bool signalingPacket = (data[0]&0xf0) == 0xf0;

				TSPSession session = null;
				if (_udpSessions.ContainsKey(endPoint)) {
					session = _udpSessions[endPoint];
				} else {
					if (signalingPacket) {
						session = new TSPSession(_sessionManager, _dbName,
						                         ProtocolType.Udp,
						                         endPoint.Address,
						                         localEndPoint.Address);
						_udpSessions.Add(endPoint, session);
					}
				}

				if (!signalingPacket) {
					if (session == null) {
						Console.WriteLine("Tunnel IP packet without initiated session!");
						continue;
					}

					// XXX: Should check that tunnel type is v6udpv4
					Console.WriteLine("Received packet from input device");
					_sessionManager.PacketFromInputDevice(data, 0, datalen);
					continue;
				}

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

				string command = Encoding.UTF8.GetString(tspData);
				session.HandleCommand(command);

				byte[] outBytes = session.DequeueResponse();
				if (outBytes == null) {
					/* Return an empty packet, shouldn't happen really */
					_udpSocket.SendTo(data, 8, SocketFlags.None, endPoint);
				} else {
					Array.Copy(outBytes, 0, data, 8, outBytes.Length);
					_udpSocket.SendTo(data, outBytes.Length+8,
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

				/* Move the bytes after first line to the beginning of the buffer */
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

				byte[] outBytes;
				session.HandleCommand(line);
				while ((outBytes = session.DequeueResponse()) != null) {
					stream.Write(outBytes, 0, outBytes.Length);
					stream.Flush();
				}
			}

			session.Cleanup();
			client.Close();
		}
	}
}
