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
		private const int CLOCK_OFF = 120;

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

				dev.SetSessionManager(this);
				_inputDevices.Add(dev);

				lock (_sessionlock) {
					foreach (TunnelType t in dev.GetSupportedTypes()) {
						/* If this TunnelType is not in sessions table, add it there */
						if (!_sessions.ContainsKey(t)) {
							_sessions.Add(t, new Dictionary<IPEndPoint, TunnelSession>());
						}
					}
				}
			}
		}

		public void AddOutputDevice(string deviceName, IPAddress ipv4, bool ipv6) {
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

				/* This should be a list of protocols with unknown EndPoint */
				if (session.TunnelType == TunnelType.Heartbeat ||
				    session.TunnelType == TunnelType.AyiyaIPv4inIPv4 ||
				    session.TunnelType == TunnelType.AyiyaIPv4inIPv6 ||
				    session.TunnelType == TunnelType.AyiyaIPv6inIPv4 ||
				    session.TunnelType == TunnelType.AyiyaIPv6inIPv6) {
					/* EndPoint not known, wait for first packet */
					_uninitiatedSessions.Add(session);
				} else {
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
				}
			}
		}

		public bool GetTunnelIPv4Endpoints(Int64 tunnelId, ref IPAddress client, ref IPAddress server) {
			if (tunnelId > 0xffffff) {
				return false;
			}

			/* XXX: Should check from OutputDevice that these are ok */
			client = IPAddress.Parse("10.123.45.2");
			server = IPAddress.Parse("10.123.45.1");

			return true;
		}

		public bool GetTunnelIPv6Endpoints(Int64 tunnelId, ref IPAddress client, ref IPAddress server) {
			if (tunnelId > 0xffffff) {
				return false;
			}

			IPAddress tunnelPrefix = null;
			foreach (OutputDevice dev in _outputDevices) {
				if (dev.IPv6TunnelPrefix != null) {
					tunnelPrefix = dev.IPv6TunnelPrefix;
				}
			}

			if (tunnelPrefix == null) {
				return false;
			}

			server = tunnelPrefix;
			byte[] clientBytes = tunnelPrefix.GetAddressBytes();
			clientBytes[13] = (byte) (tunnelId >> 16);
			clientBytes[14] = (byte) (tunnelId >> 8);
			clientBytes[15] = (byte) (tunnelId);
			client = new IPAddress(clientBytes);

			return true;
		}

		public bool UpdateSession(TunnelType type, IPEndPoint source, byte[] data) {
			TunnelSession session = null;
			lock (_sessionlock) {
				if (!_sessions.ContainsKey(type))
					return false;

				try {
					session = _sessions[type][source];
				} catch (Exception) {
				}
			}

			if (type == TunnelType.Heartbeat) {
				int strlen = data.Length;
				for (int i=0; i<data.Length; i++) {
					if (data[i] == 0) {
						strlen = i;
						break;
					} else if (data[i] < 32 || data[i] > 126) {
						Console.WriteLine("Heartbeat packet contains non-ascii characters");
						return false;
					}
				}
				string str = Encoding.ASCII.GetString(data, 0, strlen);
				if (!str.StartsWith("HEARTBEAT TUNNEL ")) {
					Console.WriteLine("Heartbeat string not found");
					return false;
				}

				IPAddress identifier = null;
				IPAddress sourceaddr = null;
				UInt32 epochtime = 0;
				
				string[] words = str.Split(' ');
				try {
					identifier = IPAddress.Parse(words[2]);
					if (words[3].Equals("sender")) {
						sourceaddr = source.Address;
					} else {
						sourceaddr = IPAddress.Parse(words[3]);
					}
					epochtime = UInt32.Parse(words[4]);
				} catch (Exception) {
					return false;
				}

				Console.WriteLine("Identifier: {0} Source: {1} Epochtime: {2}", identifier, sourceaddr, epochtime);

				/* Check for epoch time correctness */
				UInt32 epochnow = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
				int epochdiff = (int) (epochnow - epochtime);
				if (epochdiff < 0)
					epochdiff = -epochdiff;
				if (epochdiff > CLOCK_OFF) {
					Console.WriteLine("The clock is too much off ({0} seconds)", epochdiff);
					return false;
				}

				/* Session not found, check if EndPoint has changed */
				if (session == null) {
					lock (_sessionlock) {
						if (_sessions[type].ContainsKey(source)) {
							/* Weird, did someone add it? */
							session = _sessions[type][source];
						} else {
							session = findSessionByPrivateAddress(type, identifier);
							if (session != null) {
								session.EndPoint = source;
								_sessions[session.TunnelType].Add(source, session);
								_rsessions[session.AddressFamily].Add(source, session);
							}
						}
					}

					if (session == null) {
						/* Simply invalid or timed out session */
						return false;
					}
				}

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
				int length = 8 + (data[0] >> 4)*4 + (data[1] >> 4)*4;
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

				/* Check for epoch time correctness */
				UInt32 epochtime = (UInt32) ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
				UInt32 epochnow = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
				int epochdiff = (int) (epochnow - epochtime);
				if (epochdiff < 0)
					epochdiff = -epochdiff;
				if (epochdiff > CLOCK_OFF) {
					Console.WriteLine("The clock is too much off ({0} seconds)", epochdiff);
					return false;
				}

				/* Extract the identifier part from AYIYA header */
				byte[] ipaddr = new byte[((data[0] >> 4) == 1) ? 4 : 16];
				Array.Copy(data, 8, ipaddr, 0, ipaddr.Length);
				IPAddress identifier = new IPAddress(ipaddr);

				/* Session not found, check if EndPoint has changed */
				if (session == null) {
					lock (_sessionlock) {
						if (_sessions[type].ContainsKey(source)) {
							/* Weird, did someone add it? */
							session = _sessions[type][source];
						} else {
							session = findSessionByPrivateAddress(type, identifier);
							if (session != null) {
								session.EndPoint = source;
								_sessions[session.TunnelType].Add(source, session);
								_rsessions[session.AddressFamily].Add(source, session);
							}
						}
					}

					if (session == null) {
						/* Simply invalid or timed out session */
						return false;
					}
				}

				SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
				byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(session.Password));

				/* Replace the hash with password hash */
				byte[] theirHash = new byte[20];
				int hashOffset = 8 + (data[0] >> 4)*4;
				Array.Copy(data, hashOffset, theirHash, 0, 20);
				Array.Copy(passwdHash, 0, data, hashOffset, 20);

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

		private TunnelSession findSessionByPrivateAddress(TunnelType type, IPAddress address) {
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

			return null;
		}
	}
}
