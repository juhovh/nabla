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
using System.Collections.Generic;

namespace Nabla {
	public class TunnelSession {
		public readonly TunnelType TunnelType;
		public readonly AddressFamily AddressFamily;
		public IPEndPoint EndPoint;
		public string password = null;
		public DateTime LastAlive;

		public TunnelSession(TunnelType type, IPEndPoint endPoint) {
			TunnelType = type;
			switch (type) {
			case TunnelType.IPv4inIPv4:
			case TunnelType.IPv4inIPv6:
				AddressFamily = AddressFamily.InterNetwork;
				break;
			case TunnelType.IPv6inIPv4:
			case TunnelType.IPv6inIPv6:
			case TunnelType.Ayiya:
				AddressFamily = AddressFamily.InterNetworkV6;
				break;
			default:
				throw new Exception("Unknown tunnel type: " + type);
			}
			EndPoint = endPoint;
			LastAlive = DateTime.Now;
		}
	}

	public class SessionManager {
		private Object _runlock;
		private bool _running;

		private List<IntDevice> _intDevices;
		private List<ExtDevice> _extDevices;

		private Object _sessionlock;
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

		public void AddIntDevice(string deviceName, TunnelType type) {
			IntDeviceCallback callback = new IntDeviceCallback(intReceive);
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				_intDevices.Add(new IntDevice(this, deviceName, type, callback));
			}
		}

		public void AddExtDevice(string deviceName) {
			ExtDeviceCallback callback = new ExtDeviceCallback(extReceive);
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				_extDevices.Add(new ExtDevice(deviceName, callback));
			}
		}

		public void AddSession(TunnelSession session) {
			lock (_sessionlock) {
				if (!_sessions.ContainsKey(session.TunnelType)) {
					throw new Exception("Session with unconfigured type: " + session.TunnelType);
				}

				if (_sessions[session.TunnelType].ContainsKey(session.EndPoint)) {
					throw new Exception("Session with type " + session.TunnelType + " and EndPoint " + session.EndPoint + " already exists");
				}

				if (_rsessions[session.AddressFamily].ContainsKey(session.EndPoint)) {
					throw new Exception("Session with family " + session.AddressFamily + " and EndPoint " + session.EndPoint + " already exists");
				}

				_sessions[session.TunnelType][session.EndPoint] = session;
				_rsessions[session.AddressFamily][session.EndPoint] = session;
			}
		}

		public bool SessionAlive(TunnelType type, IPEndPoint source, byte[] data) {
			TunnelSession session;
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

		public void Start() {
			lock (_runlock) {
				if (_running) {
					return;
				}

				foreach (IntDevice dev in _intDevices) {
					dev.Start();
				}
				foreach (ExtDevice dev in _extDevices) {
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

				foreach (IntDevice dev in _intDevices) {
					dev.Stop();
				}
				foreach (ExtDevice dev in _extDevices) {
					dev.Stop();
				}
				_running = false;
			}
		}

		private void intReceive(TunnelType type, IPEndPoint source, byte[] data) {
			foreach (ExtDevice dev in _extDevices) {
				dev.SendPacket(source, data);
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

			foreach (IntDevice dev in _intDevices) {
				if (dev.TunnelType == session.TunnelType) {
					dev.SendPacket(destination, data);
				}
			}
		}
	}
}
