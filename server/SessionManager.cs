/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009-2010  Juho Vähä-Herttua
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
		private Dictionary<Int64, TunnelSession> _sessions = new Dictionary<Int64, TunnelSession>();

		public SessionManager() {
		}

		public void AddInputDevice(InputDevice dev) {
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				lock (_sessionlock) {
					// Check that this type is not already added
					dev.SetSessionManager(this);
					_inputDevices.Add(dev);
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
			if (session == null) {
				return;
			}

			_sessions[session.TunnelId] = session;
		}

		public Int64 TunnelIdFromAddress(IPAddress remoteAddress) {
			Int64 tunnelId = 0;

			if (remoteAddress.AddressFamily == AddressFamily.InterNetwork) {
				byte[] addrBytes = remoteAddress.GetAddressBytes();

				tunnelId += (Int64) (addrBytes[1] << 14);
				tunnelId += (Int64) (addrBytes[2] << 6);
				tunnelId += (Int64) ((addrBytes[3]&0xfc) >> 2);
			} else if (remoteAddress.AddressFamily == AddressFamily.InterNetworkV6) {
				byte[] addrBytes = remoteAddress.GetAddressBytes();

				tunnelId += (Int64) (addrBytes[10] << 16);
				tunnelId += (Int64) (addrBytes[11] << 8);
				tunnelId += (Int64) (addrBytes[12]);
			} else {
				return -1;
			}

			if (!_sessions.ContainsKey(tunnelId)) {
				return -1;
			}

			return tunnelId;
		}

		public void UpdateSession(IPAddress remoteAddress, IPEndPoint endPoint) {
			Int64 tunnelId = TunnelIdFromAddress(remoteAddress);
			TunnelSession session = _sessions[tunnelId];
			session.EndPoint = endPoint;
			// XXX: Update the last alive
		}

		public IPEndPoint GetSessionEndPoint(Int64 tunnelId) {
			// XXX: Check that the session exists
			return _sessions[tunnelId].EndPoint;
		}

		public string GetSessionPassword(Int64 tunnelId) {
			// XXX: Check that the session exists
			return _sessions[tunnelId].Password;
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
		 * data - actual packet bytes
		 * offset - offset where the actual data of the packet begins
		 * length - length of the data in bytes */
		public void PacketFromInputDevice(byte[] data, int offset, int length) {
			if (offset+length > data.Length) {
				/* Not enough data to work on */
				return;
			}

			IPAddress source;
			int version = ((data[offset]&0xff) >> 4);
			if (version == 4) {
				if (length < 20) {
					/* Not enough bytes for IPv4 header */
					return;
				}

				byte[] ipaddr = new byte[4];
				Array.Copy(data, offset+12, ipaddr, 0, 4);
				source = new IPAddress(ipaddr);
			} else if (version == 6) {
				if (length < 40) {
					/* Not enough bytes for IPv6 header */
					return;
				}

				byte[] ipaddr = new byte[16];
				Array.Copy(data, offset+8, ipaddr, 0, 16);
				source = new IPAddress(ipaddr);
			} else {
				/* Unknown protocol version */
				return;
			}

			Int64 tunnelId = TunnelIdFromAddress(source);
			Console.WriteLine("Got tunnel id " + tunnelId + " for source " + source);
			if (tunnelId < 0) {
				return;
			}

			// XXX: Should check if the session is alive

			byte[] outdata = new byte[length];
			Array.Copy(data, offset, outdata, 0, length);

			foreach (OutputDevice dev in _outputDevices) {
				try {
					dev.SendPacket(outdata);
				} catch (Exception e) {
					Console.WriteLine("Exception sending packet: " + e);
				}
			}
		}

		/* Incoming packet from an OutputDevice.
		 * data - actual packet bytes
		 * offset - offset where the actual data of the packet begins
		 * length - length of the data in bytes */
		private void packetFromOutputDevice(byte[] data, int offset, int length) {
			if (offset+length > data.Length) {
				/* Not enough data to work on */
				return;
			}

			IPAddress destination;
			int version = ((data[offset]&0xff) >> 4);
			if (version == 4) {
				if (length < 20) {
					/* Not enough bytes for IPv4 header */
					return;
				}

				byte[] ipaddr = new byte[4];
				Array.Copy(data, offset+16, ipaddr, 0, 4);
				destination = new IPAddress(ipaddr);
			} else if (version == 6) {
				if (length < 40) {
					/* Not enough bytes for IPv6 header */
					return;
				}

				byte[] ipaddr = new byte[16];
				Array.Copy(data, offset+24, ipaddr, 0, 16);
				destination = new IPAddress(ipaddr);
			} else {
				/* Unknown protocol version */
				return;
			}

			Int64 tunnelId = TunnelIdFromAddress(destination);
			Console.WriteLine("Got tunnel id " + tunnelId + " for destination " + destination);
			if (tunnelId < 0) {
				return;
			}

			if (!_sessions.ContainsKey(tunnelId)) {
				return;
			}

			// XXX: Should check if the session is alive

			byte[] outdata = new byte[length];
			Array.Copy(data, offset, outdata, 0, length);

			TunnelSession session = _sessions[tunnelId];
			foreach (InputDevice dev in _inputDevices) {
				foreach (TunnelType t in dev.GetSupportedTypes()) {
					if (t == session.TunnelType) {
						dev.SendPacket(tunnelId, data);
						break;
					}
				}
			}
		}

	}
}
