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
using Nabla.Database;

namespace Nabla {
	public class TICServer {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private SessionManager _sessionManager;
		private TcpListener _listener;
		private Thread _thread;

		/* Use the default port */
		public TICServer(SessionManager sessionManager, string deviceName) :
			this(sessionManager, deviceName, 3874) {}

		public TICServer(SessionManager sessionManager, string deviceName, int port) {
			InputDevice dev;
			dev = new GenericInputDevice(deviceName, GenericInputType.IPv6inIPv4);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(deviceName, GenericInputType.IPv4inIPv6);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(deviceName, GenericInputType.Heartbeat);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(deviceName, GenericInputType.Ayiya);
			sessionManager.AddInputDevice(dev);

			using (UserDatabase db = new UserDatabase("nabla.db")) {
				TunnelInfo[] tunnels = db.ListTunnels(0, "tic");
				foreach (TunnelInfo t in tunnels) {
					IPAddress privateAddress = sessionManager.GetIPv6TunnelEndpoint(t.TunnelId);
					if (privateAddress == null) {
						Console.WriteLine("Session not added, IPv6 maybe not enabled?");
						continue;
					}

					TunnelSession session = null;
					if (t.Endpoint.Equals("ayiya")) {
						session = new TunnelSession(TunnelType.AyiyaIPv6,
						                            privateAddress,
						                            t.Password);
					} else if (t.Endpoint.Equals("heartbeat")) {
						session = new TunnelSession(TunnelType.Heartbeat,
						                            privateAddress,
						                            t.Password);
					} else {
						IPAddress address = IPAddress.Parse(t.Endpoint);
						IPEndPoint endPoint = new IPEndPoint(address, 0);

						TunnelType type;
						if (address.AddressFamily == AddressFamily.InterNetwork) {
							type = TunnelType.IPv6inIPv4;
						} else {
							type = TunnelType.IPv4inIPv6;
						}

						session = new TunnelSession(type, endPoint);
					}

					sessionManager.AddSession(session);
				}
			}

			_sessionManager = sessionManager;
			_listener = new TcpListener(IPAddress.IPv6Any, port);
		}

		public void Start() {
			lock (_runlock) {
				_running = true;
				_listener.Start();
				_thread = new Thread(new ThreadStart(listenerThread));
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

		private void listenerThread() {
			while (_running) {
				TcpClient client = _listener.AcceptTcpClient();

				Thread thread = new Thread(new ParameterizedThreadStart(sessionThread));
				thread.Start(client);
			}
		}

		private void sessionThread(object data) {
			TcpClient client = (TcpClient) data;

			string serviceName = "Nabla";
			string serviceUrl = "http://code.google.com/p/nabla/";

			IPEndPoint remoteEndPoint = InputDevice.GetIPEndPoint(client.Client.RemoteEndPoint);
			IPEndPoint localEndPoint = InputDevice.GetIPEndPoint(client.Client.LocalEndPoint);
			TICSession session = new TICSession(_sessionManager, serviceName,
			                                    remoteEndPoint.Address, localEndPoint.Address);

			StreamReader reader = new StreamReader(client.GetStream());
			StreamWriter writer = new StreamWriter(client.GetStream());

			/* Write the initial welcome line */
			writer.WriteLine("200 " + serviceName + " TIC Service on " + Dns.GetHostName() + " ready" +
			                 " (" + serviceUrl + ")");
			writer.Flush();

			while (!session.Finished()) {
				string line = null;
				try {
					line = reader.ReadLine().Trim();
				} catch (Exception) {
					break;
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
