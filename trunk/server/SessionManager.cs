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
	public class TunnelSession {
		public readonly TunnelType TunnelType;
		public readonly AddressFamily AddressFamily;
		public IPEndPoint EndPoint;
		public string Password = null;
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

			if (type == TunnelType.Ayiya) {
				if (data[0] != 0x41 || // IDlen = 4, IDtype = integer
				    data[1] != 0x52 || // siglen = 5, method = SHA1
				    // auth = sharedsecret, opcode = noop | forward | echo response
				    (data[2] != 0x10 && data[2] != 0x11 && data[2] != 0x14) ||
				    // next header = ipv6 | none
				    (data[3] != 41 && data[3] != 59)) {
					Console.WriteLine("Received an invalid AYIYA packet");
					return false;
				}

				/* Default size of AYIYA header */
				int datalen = 52;
				if (data[3] == 41) {
					/* In case of IPv6, add the header and payload lengths */
					datalen += 40 + data[datalen+4]*256 + data[datalen+5];
				}

				SHA1Managed sha1 = new SHA1Managed();
				byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(session.Password));

				/* Replace the hash with password hash */
				byte[] theirHash = new byte[40];
				Array.Copy(data, 32, theirHash, 0, 20);
				Array.Copy(passwdHash, 0, data, 32, 20);

				byte[] ourHash = sha1.ComputeHash(data, 0, datalen);
				if (!BitConverter.ToString(ourHash).Equals(BitConverter.ToString(theirHash))) {
					Console.WriteLine("Incorrect AYIYA hash");
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
