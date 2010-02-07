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
			OutputDeviceCallback callback = new OutputDeviceCallback(packetFromOutputDevice);
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

				if (session.EndPoint == null && session.Password != null) {
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
					throw new Exception("Session without EndPoint and Password");
				}

				Console.WriteLine("\nModified session:\n" + session + "\n");
			}
		}

		/* This is simply a helper function that changes the endpoint and then adds
		 * the session to the session arrays. It's here because the updated session
		 * might be an unitialized session that needs to be added. This is ugly though */
		public bool UpdateSession(TunnelSession session, IPEndPoint endpoint) {
			try {
				session.EndPoint = endpoint;
				AddSession(session);
				return true;
			} catch (Exception) {}

			return false;
		}

		public TunnelSession GetSession(TunnelType type, IPEndPoint source, IPAddress address) {
			lock (_sessionlock) {
				Console.WriteLine("Getting session for type " + type);
				if (_sessions[type].ContainsKey(source)) {
					return _sessions[type][source];
				}

				if (address == null) {
					/* Unable to fetch by address */
					return null;
				}

				foreach (TunnelSession ts in _sessions[type].Values) {
					IPAddress gwaddr = ts.RemoteAddress;
					if (gwaddr != null && gwaddr.Equals(address)) {
						_sessions[ts.TunnelType].Remove(ts.EndPoint);
						_rsessions[ts.AddressFamily].Remove(ts.EndPoint);
						return ts;
					}
				}

				foreach (TunnelSession ts in _uninitiatedSessions) {
					if (type == ts.TunnelType && address.Equals(ts.RemoteAddress)) {
						_uninitiatedSessions.Remove(ts);
						return ts;
					}
				}
			}

			return null;
		}

		private bool sessionAlive(TunnelType type, IPEndPoint source) {
			TunnelSession session = null;
			lock (_sessionlock) {
				try {
					session = _sessions[type][source];
				} catch (Exception) {
					return false;
				}
			}


			/* XXX: Check that the session is alive by setting some timeout value... */
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
			if (tunnelId > 0x3fffff) {
				return null;
			}

			byte[] addrBytes = new byte[4];
			addrBytes[0] = 10;
			addrBytes[1] = (byte) ((tunnelId >> 14) & 0xff);
			addrBytes[2] = (byte) ((tunnelId >>  6) & 0xff);
			addrBytes[3] = (byte) ((tunnelId <<  2) & 0xfc);

			/* Remote address is the second one in subnet */
			addrBytes[3] |= 0x02;

			return new IPAddress(addrBytes);
		}

		public IPAddress GetIPv4TunnelLocalAddress(Int64 tunnelId) {
			if (tunnelId > 0x3fffff) {
				return null;
			}

			byte[] addrBytes = new byte[4];
			addrBytes[0] = 10;
			addrBytes[1] = (byte) ((tunnelId >> 14) & 0xff);
			addrBytes[2] = (byte) ((tunnelId >>  6) & 0xff);
			addrBytes[3] = (byte) ((tunnelId <<  2) & 0xfc);

			/* Local address is the first one in subnet */
			addrBytes[3] |= 0x01;

			return new IPAddress(addrBytes);
		}

		public bool IPv6IsAvailable {
			get {
				IPAddress localAddress = null;
				foreach (OutputDevice dev in _outputDevices) {
					if (dev.IPv6LocalAddress != null) {
						localAddress = dev.IPv6LocalAddress;
						break;
					}
				}

				return (localAddress != null);
			}
		}

		public IPAddress GetIPv6TunnelRemoteAddress(Int64 tunnelId) {
			if (tunnelId > 0xffffff) {
				return null;
			}

			IPAddress localAddress = null;
			foreach (OutputDevice dev in _outputDevices) {
				if (dev.IPv6LocalAddress != null) {
					localAddress = dev.IPv6LocalAddress;
					break;
				}
			}

			if (localAddress == null) {
				return null;
			}

			/* Construct the remote address from the local address */
			byte[] ipaddr = localAddress.GetAddressBytes();
			ipaddr[10] = (byte) (tunnelId >> 16);
			ipaddr[11] = (byte) (tunnelId >> 8);
			ipaddr[12] = (byte) (tunnelId);

			return new IPAddress(ipaddr);
		}

		public IPAddress GetIPv6TunnelLocalAddress(Int64 tunnelId) {
			IPAddress localAddress = null;
			foreach (OutputDevice dev in _outputDevices) {
				if (dev.IPv6LocalAddress != null) {
					localAddress = dev.IPv6LocalAddress;
					break;
				}
			}

			return localAddress;
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

		/* Incoming packet from an InputDevice.
		 * type - type of the tunnel sending this data through, indicates the encapsulation type
		 * source - the source address and port where the encapsulated packet is originally coming from
		 * data - actual packet bytes
		 * offset - offset where the actual data of the packet begins
		 * length - length of the data in bytes */
		public void PacketFromInputDevice(TunnelType type, IPEndPoint source, byte[] data, int offset, int length) {
			if (!sessionAlive(type, source)) {
				return;
			}

			byte[] outdata = new byte[length];
			Array.Copy(data, offset, outdata, 0, length);

			foreach (OutputDevice dev in _outputDevices) {
				try {
					dev.SendPacket(source, outdata);
				} catch (Exception e) {
					Console.WriteLine("Exception sending packet: " + e);
				}
			}
		}

		/* Incoming packet from an OutputDevice.
		 * family - the address family of the data packet that was received
		 * destination - the destination address and port where the encapsulated tunnel packet should be sent
		 * data - actual packet bytes */
		private void packetFromOutputDevice(AddressFamily family, IPEndPoint destination, byte[] data) {
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
