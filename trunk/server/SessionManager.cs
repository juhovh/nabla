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
			case TunnelType.AyiyaIPv4inIPv4:
			case TunnelType.AyiyaIPv4inIPv6:
				AddressFamily = AddressFamily.InterNetwork;
				break;
			case TunnelType.IPv6inIPv4:
			case TunnelType.IPv6inIPv6:
			case TunnelType.Heartbeat:
			case TunnelType.AyiyaIPv6inIPv4:
			case TunnelType.AyiyaIPv6inIPv6:
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
		private Object _runlock = new Object();
		private bool _running;

		private List<IntDevice> _intDevices = new List<IntDevice>();
		private List<ExtDevice> _extDevices = new List<ExtDevice>();

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

		public void AddIntDevice(string deviceName, TunnelType type) {
			IntDeviceCallback callback = new IntDeviceCallback(intReceive);
			lock (_runlock) {
				if (_running) {
					throw new Exception("Can't add devices while running, stop the manager first");
				}

				_intDevices.Add(new IntDevice(this, deviceName, type, callback));

				lock (_sessionlock) {
					/* If this TunnelType is not in sessions table, add it there */
					if (!_sessions.ContainsKey(type)) {
						_sessions.Add(type,
							      new Dictionary<IPEndPoint, TunnelSession>());
					}
				}
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

				/* This should be a list of protocols over UDP/TCP */
				if (session.TunnelType == TunnelType.AyiyaIPv4inIPv4 ||
				    session.TunnelType == TunnelType.AyiyaIPv4inIPv6 ||
				    session.TunnelType == TunnelType.AyiyaIPv6inIPv4 ||
				    session.TunnelType == TunnelType.AyiyaIPv6inIPv6) {
					/* Remote port not known, wait for first packet */
					_uninitiatedSessions.Add(session);
				} else {
					_sessions[session.TunnelType][session.EndPoint] = session;
					_rsessions[session.AddressFamily][session.EndPoint] = session;
				}
			}
		}

		public bool UpdateSession(TunnelType type, IPEndPoint source, byte[] data) {
			TunnelSession session = null;
			lock (_sessionlock) {
				if (!_sessions.ContainsKey(type))
					return false;

				try {
					session = _sessions[type][source];
				} catch (Exception) {
					foreach (TunnelSession s in _uninitiatedSessions) {
						if (type == s.TunnelType && source.Address.Equals(s.EndPoint.Address)) {
							/* Initiate the session because it was requested */
//							_uninitiatedSessions.Remove(s);
							s.EndPoint = source;
							_sessions[s.TunnelType][s.EndPoint] = s;
							_rsessions[s.AddressFamily][s.EndPoint] = s;
							session = s;
						}
					}
				}
			}

			if (type == TunnelType.Heartbeat) {
				int strlen = data.Length;
				for (int i=0; i<data.Length; i++) {
					if (data[i] == 0) {
						strlen = i;
						break;
					} else if (data[i] < 32 || data[i] > 126) {
						Console.WriteLine("Invalid heartbeat packet");
						return false;
					}
				}
				string str = Encoding.ASCII.GetString(data, 0, strlen);
				if (str.IndexOf("HEARTBEAT TUNNEL ") != 0) {
					Console.WriteLine("Heartbeat string not found");
					return false;
				}

				IPAddress identifier = null;
				UInt32 epochtime = 0;
				try {
					string[] words = str.Split(' ');
					identifier = IPAddress.Parse(words[2]);
					epochtime = UInt32.Parse(words[3]);
				} catch (Exception) {
					return false;
				}

				Console.WriteLine("Identifier: {0} Epochtime: {1}", identifier, epochtime);
				Console.WriteLine("Identifier: " + identifier);
				/* XXX: Check for epoch time */
				/* XXX: Check if session is invalid */

				MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
				byte[] passwdHash = md5.ComputeHash(Encoding.ASCII.GetBytes(session.Password));
				
				string theirHashStr = str.Substring(str.Length-32, 32);
				str = str.Substring(0, str.Length-32);
				str += BitConverter.ToString(passwdHash).Replace("-", "").ToLower();
				
				byte[] ourHash = md5.ComputeHash(Encoding.ASCII.GetBytes(str));
				string ourHashStr = BitConverter.ToString(ourHash).Replace("-", "").ToLower();

				if (!theirHashStr.Equals(ourHashStr)) {
					Console.WriteLine("Incorrect Heartbeat hash");
					return false;
				}
			} else {
				if ((data[0] != 0x11 && data[0] != 0x41) || // IDlen = 1 | 4, IDtype = int
				     data[1] != 0x52 || // siglen = 5, method = SHA1
				    // auth = sharedsecret, opcode = noop | forward | echo response
				    (data[2] != 0x10 && data[2] != 0x11 && data[2] != 0x14)) {
					return false;
				}

				/* Start with the size of AYIYA header */
				int length = 4 + (data[0] >> 4)*4 + (data[1] >> 4)*4;
				if (data[3] == 4) { /* IPPROTO_IPIP */
					if (type != TunnelType.AyiyaIPv4inIPv4 &&
					    type != TunnelType.AyiyaIPv4inIPv6) {
						return false;
					}

					/* In case of IPv4, add the header and payload lengths */
					length += (data[length] & 0x0f)*4 + data[length+2]*256 + data[length+3];
				} else if (data[3] == 41) { /* IPPROTO_IPV6 */
					if (type != TunnelType.AyiyaIPv6inIPv4 &&
					    type != TunnelType.AyiyaIPv6inIPv6) {
						return false;
					}

					/* In case of IPv6, add the header and payload lengths */
					length += 40 + data[length+4]*256 + data[length+5];
				} else if (data[3] == 59) { /* IPPROTO_NONE */
					/* In case of no content, opcode should be nop or echo response */
					if ((data[2] & 0x0f) != 0 || (data[2] & 0x0f) != 4) {
						return false;
					}
				} else {
					Console.WriteLine("Invalid next header in AYIYA packet: " + data[3]);
					return false;
				}

				/* XXX: Check for epoch time */

				SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
				byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(session.Password));

				/* Replace the hash with password hash */
				byte[] theirHash = new byte[40];
				Array.Copy(data, 32, theirHash, 0, 20);
				Array.Copy(passwdHash, 0, data, 32, 20);

				byte[] ourHash = sha1.ComputeHash(data, 0, length);
				if (!BitConverter.ToString(ourHash).Equals(BitConverter.ToString(theirHash))) {
					Console.WriteLine("Incorrect AYIYA hash");
					return false;
				}
			}

			return true;
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
