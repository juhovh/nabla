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
using System.Text;
using System.Threading;
using Nabla.Database;

namespace Nabla {
	public class TICServer : InputDevice {
		private Object _runlock = new Object();
		private volatile bool _running = false;

		private string _dbName;
		private string _deviceName;
		private TcpListener _listener;
		private SessionManager _sessionManager;
		private Thread _thread;

		/* Use the default port */
		public TICServer(string dbName, string deviceName) :
			this(dbName, deviceName, 3874) {}

		public TICServer(string dbName, string deviceName, int port) {
			_dbName = dbName;
			_deviceName = deviceName;
			_listener = new TcpListener(IPAddress.IPv6Any, port);
		}

		public override void SetSessionManager(SessionManager sessionManager) {
			InputDevice dev;

			/* All input tunnel types used by TIC should be listed here */
/*
			dev = new GenericInputDevice(_deviceName, GenericInputType.IPv6inIPv4);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(_deviceName, GenericInputType.IPv4inIPv6);
			sessionManager.AddInputDevice(dev);
			dev = new GenericInputDevice(_deviceName, GenericInputType.Heartbeat);
			sessionManager.AddInputDevice(dev);
*/
			dev = new GenericInputDevice(_deviceName, GenericInputType.Ayiya);
			sessionManager.AddInputDevice(dev);

			using (UserDatabase db = new UserDatabase(_dbName)) {
				TunnelInfo[] tunnels = db.ListTunnels("tic");

				/* Iterate through the tunnels and add each tunnel session to the session manager */
				foreach (TunnelInfo t in tunnels) {

					/* Get the IPv6 address that is reserved for the server and this tunnel endpoint */
					IPAddress remoteAddress = sessionManager.GetIPv6TunnelRemoteAddress(t.TunnelId);

					/* AYIYA and Heartbeat both require sessions to be available */
					if ((t.Endpoint.Equals("ayiya") || t.Endpoint.Equals("heartbeat")) && remoteAddress == null) {
						/* SessionManager couldn't find an address to this endpoint, maybe we have
						 * exceeded the number of tunnels or IPv6 wasn't found in output device */

						Console.WriteLine("Session not added, IPv6 maybe not enabled?");
						continue;
					}

					if (!t.Enabled || !t.UserEnabled) {
						Console.WriteLine("Tunnel T" + t.TunnelId + " not enabled, session not added");
					}

					TunnelSession session = null;
					if (t.Endpoint.Equals("ayiya")) {
						session = new TunnelSession(t.TunnelId, TunnelType.AyiyaIPv6,
						                            t.Password);
					} else if (t.Endpoint.Equals("heartbeat")) {
						session = new TunnelSession(t.TunnelId, TunnelType.Heartbeat,
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

						session = new TunnelSession(t.TunnelId, type, endPoint);
					}

					sessionManager.AddSession(session);
				}
			}

			_sessionManager = sessionManager;
		}

		public override TunnelType[] GetSupportedTypes() {
			return new TunnelType[] {};
		}

		public override void Start() {
			lock (_runlock) {
				_running = true;
				_listener.Start();
				_thread = new Thread(new ThreadStart(listenerThread));
				_thread.Start();
			}
		}

		public override void Stop() {
			lock (_runlock) {
				_running = false;
				_thread.Join();
				_listener.Stop();
			}
		}

		public override void SendPacket(Int64 tunnelId, byte[] data) {
			/* Never called because we have no types set */
			throw new Exception("Send packet called on TICServer");
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
			TICSession session = new TICSession(_sessionManager, _dbName, serviceName,
			                                    remoteEndPoint.Address, localEndPoint.Address);

			// XXX: Should use UTF-8 but we don't want the BOM...
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
