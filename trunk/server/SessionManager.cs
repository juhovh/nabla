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
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Nabla {
	public class SessionManager {
		private Object _runlock = new Object();
		private bool _running;

		private List<InputDevice> _inputDevices = new List<InputDevice>();
		private List<OutputDevice> _outputDevices = new List<OutputDevice>();

		private Object _sessionlock = new Object();
		private List<TunnelSession> _uninitiatedSessions = new List<TunnelSession>();
		private Dictionary<TunnelType, Dictionary<IPEndPoint, TunnelSession>> _sessions
			= new Dictionary<TunnelType, Dictionary<IPEndPoint, TunnelSession>>();
		private Dictionary<AddressFamily, Dictionary<IPEndPoint, TunnelSession>> _rsessions
			= new Dictionary<AddressFamily, Dictionary<IPEndPoint, TunnelSession>>();

		public SessionManager() {
			/* Only these two protocols are supported, so we can add both */
			_rsessions.Add(AddressFamily.InterNetwork,
			               new Dictionary<IPEndPoint, TunnelSession>());
			_rsessions.Add(AddressFamily.InterNetworkV6,
			               new Dictionary<IPEndPoint, TunnelSession>());
		}

		public void AddInputDevice(InputDevice dev) {
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				lock (_sessionlock) {
					bool missing = true;

					dev.SetSessionManager(this);
					foreach (TunnelType t in dev.GetSupportedTypes()) {
						/* If this TunnelType is not in sessions table, add it there */
						if (!_sessions.ContainsKey(t)) {
							_sessions.Add(t, new Dictionary<IPEndPoint, TunnelSession>());
							missing = true;
						}
					}

					if (missing || dev.GetSupportedTypes().Length == 0) {
						_inputDevices.Add(dev);
					}
				}
			}
		}

		public void AddOutputDevice(string deviceName, bool ipv4, bool ipv6) {
			OutputDeviceCallback callback = new OutputDeviceCallback(extReceive);
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				_outputDevices.Add(new OutputDevice(deviceName, ipv4, ipv6, callback));
			}
		}

		public void AddSession(TunnelSession session) {
			lock (_sessionlock) {
				if (!_sessions.ContainsKey(session.TunnelType)) {
					throw new Exception("Session with unconfigured type: " + session.TunnelType);
				}

				if (session.EndPoint == null && session.PrivateAddress != null) {
					/* EndPoint not known, wait for first packet */
					_uninitiatedSessions.Add(session);
				} else if (session.EndPoint != null) {
					if (_sessions[session.TunnelType].ContainsKey(session.EndPoint)) {
						throw new Exception("Session with type " + session.TunnelType +
						                    " and EndPoint " + session.EndPoint +
						                    " already exists");
					}

					if (_rsessions[session.AddressFamily].ContainsKey(session.EndPoint)) {
						throw new Exception("Session with family " + session.AddressFamily +
						                    " and EndPoint " + session.EndPoint +
						                    " already exists");
					}

					_sessions[session.TunnelType][session.EndPoint] = session;
					_rsessions[session.AddressFamily][session.EndPoint] = session;
				} else {
					throw new Exception("Session without EndPoint and PrivateAddress");
				}

				Console.WriteLine("Added new session:\n" + session);
			}
		}

		public TunnelSession GetSession(TunnelType type, IPEndPoint source, IPAddress address) {
			lock (_sessionlock) {
				if (_sessions[type].ContainsKey(source)) {
					return _sessions[type][source];
				}

				if (address == null) {
					/* Unable to fetch by address */
					return null;
				}

				foreach (TunnelSession ts in _sessions[type].Values) {
					IPAddress gwaddr = ts.PrivateAddress;
					if (gwaddr != null && gwaddr.Equals(address)) {
						_sessions[ts.TunnelType].Remove(ts.EndPoint);
						_rsessions[ts.AddressFamily].Remove(ts.EndPoint);
						return ts;
					}
				}

				foreach (TunnelSession ts in _uninitiatedSessions) {
					if (type == ts.TunnelType && address.Equals(ts.PrivateAddress)) {
						_uninitiatedSessions.Remove(ts);
						return ts;
					}
				}
			}

			return null;
		}

		public bool UpdateSession(TunnelSession session, IPEndPoint source) {
			try {
				session.EndPoint = source;
				AddSession(session);
				return true;
			} catch (Exception) {}

			return false;
		}

		public bool SessionAlive(TunnelType type, IPEndPoint source) {
			TunnelSession session = null;
			lock (_sessionlock) {
				try {
					session = _sessions[type][source];
				} catch (Exception) {
					return false;
				}
			}


			/* XXX: Check that the session is alive */
			if (DateTime.Now - session.LastAlive > TimeSpan.Zero) {
				return true;
			}

			return false;
		}

		public bool IPv4IsAvailable {
			get {
				// XXX: Should return the real availability
				return true;
			}
		}

		public IPAddress GetIPv4TunnelRemoteAddress(Int64 tunnelId) {
			if (tunnelId > 0xffffff) {
				return null;
			}

			/* XXX: Should check from OutputDevice that this is ok */
			return IPAddress.Parse("10.123.45.2");
		}

		public IPAddress GetIPv4TunnelLocalAddress(Int64 tunnelId) {
			/* XXX: Should check from OutputDevice that this is ok */
			return IPAddress.Parse("10.123.45.1");
		}

		public bool IPv6IsAvailable {
			get {
				IPAddress tunnelPrefix = null;
				foreach (OutputDevice dev in _outputDevices) {
					if (dev.IPv6TunnelPrefix != null) {
						tunnelPrefix = dev.IPv6TunnelPrefix;
						break;
					}
				}

				return (tunnelPrefix != null);
			}
		}

		public IPAddress GetIPv6TunnelRemoteAddress(Int64 tunnelId) {
			if (tunnelId > 0xffffff) {
				return null;
			}

			IPAddress tunnelPrefix = null;
			foreach (OutputDevice dev in _outputDevices) {
				if (dev.IPv6TunnelPrefix != null) {
					tunnelPrefix = dev.IPv6TunnelPrefix;
					break;
				}
			}

			if (tunnelPrefix == null) {
				return null;
			}

			byte[] ipaddr = tunnelPrefix.GetAddressBytes();
			ipaddr[13] = (byte) (tunnelId >> 16);
			ipaddr[14] = (byte) (tunnelId >> 8);
			ipaddr[15] = (byte) (tunnelId);

			return new IPAddress(ipaddr);
		}

		public IPAddress GetIPv6TunnelLocalAddress(Int64 tunnelId) {
			IPAddress tunnelPrefix = null;
			foreach (OutputDevice dev in _outputDevices) {
				if (dev.IPv6TunnelPrefix != null) {
					tunnelPrefix = dev.IPv6TunnelPrefix;
					break;
				}
			}

			if (tunnelPrefix == null) {
				return null;
			}

			return tunnelPrefix;
		}

		public void Start() {
			lock (_runlock) {
				if (_running) {
					return;
				}

				foreach (InputDevice dev in _inputDevices) {
					dev.Start();
				}
				foreach (OutputDevice dev in _outputDevices) {
					dev.Start();
				}
				_running = true;
			}
		}

		public void Stop() {
			lock (_runlock) {
				if (!_running) {
					return;
				}

				foreach (InputDevice dev in _inputDevices) {
					dev.Stop();
				}
				foreach (OutputDevice dev in _outputDevices) {
					dev.Stop();
				}
				_running = false;
			}
		}

		public void ProcessPacket(TunnelType type, IPEndPoint source, byte[] data) {
			foreach (OutputDevice dev in _outputDevices) {
				try {
					dev.SendPacket(source, data);
				} catch (Exception e) {
					Console.WriteLine("Exception sending packet: " + e);
				}
			}
		}

		private void extReceive(AddressFamily family, IPEndPoint destination, byte[] data) {
			TunnelSession session;

			lock (_sessionlock) {
				try {
					session = _rsessions[family][destination];
				} catch (Exception) {
					/* Unknown protocol or destination, drop packet */
					return;
				}
			}

			foreach (InputDevice dev in _inputDevices) {
				foreach (TunnelType t in dev.GetSupportedTypes()) {
					if (t == session.TunnelType) {
						dev.SendPacket(session, data);
						break;
					}
				}
			}
		}

	}
}
