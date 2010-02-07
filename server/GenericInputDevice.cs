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
using System.Threading;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using Nabla.Sockets;

namespace Nabla {
	public class GenericInputDevice : InputDevice {
		private const int CLOCK_MAX_OFFSET = 120;
		private const int waitms = 100;

		private TunnelType _type;

		private Thread _thread;
		private volatile bool _running;

		private SessionManager _sessionManager;

		private Socket _udpSocket = null;
		private RawSocket _rawSocket = null;

		public GenericInputDevice(string deviceName, TunnelType type) {
			_type = type;

			AddressFamily addressFamily = AddressFamily.Unknown;
			int protocol = 0;

			switch (type) {
			case TunnelType.AYIYAinIPv4:
				_udpSocket = new Socket(AddressFamily.InterNetwork,
				                        SocketType.Dgram,
				                        ProtocolType.Udp);
				_udpSocket.Bind(new IPEndPoint(IPAddress.Any, 5072));
				break;
			case TunnelType.Heartbeat:
				addressFamily = AddressFamily.InterNetwork;
				_udpSocket = new Socket(AddressFamily.InterNetwork,
				                        SocketType.Dgram,
				                        ProtocolType.Udp);
				_udpSocket.Bind(new IPEndPoint(IPAddress.Any, 3740));
				break;
			case TunnelType.IPv4inIPv4:
				addressFamily = AddressFamily.InterNetwork;
				protocol = 4;
				break;
			case TunnelType.IPv4inIPv6:
				addressFamily = AddressFamily.InterNetworkV6;
				protocol = 4;
				break;
			case TunnelType.IPv6inIPv4:
				addressFamily = AddressFamily.InterNetwork;
				protocol = 41;
				break;
			case TunnelType.IPv6inIPv6:
				addressFamily = AddressFamily.InterNetworkV6;
				protocol = 41;
				break;
			default:
				throw new Exception("Unsupported input type: " + type);
			}

			if (addressFamily != AddressFamily.Unknown) {
				_rawSocket = RawSocket.GetRawSocket(deviceName, addressFamily, protocol, waitms);
			}

			_thread = new Thread(new ThreadStart(this.threadLoop));
		}

		public override void SetSessionManager(SessionManager sessionManager) {
			_sessionManager = sessionManager;
		}

		public override TunnelType[] GetSupportedTypes() {
			return new TunnelType[] { _type };
		}

		public override void Start() {
			_running = true;
			_thread.Start();
		}

		public override void Stop() {
			_running = false;
			_thread.Join();
		}

		public override void SendPacket(Int64 tunnelId, byte[] data) {
			IPEndPoint endPoint = _sessionManager.GetSessionEndPoint(tunnelId);
			if (endPoint == null) {
				return;
			}

			if (_type == TunnelType.AYIYAinIPv4) {
				// FIXME: Not necessarily IPv6, could be also IPv4
				IPAddress localAddress = _sessionManager.GetIPv6TunnelLocalAddress(tunnelId);
				string password = _sessionManager.GetSessionPassword(tunnelId);

				int datalen = 40 + data[4]*256 + data[5];

				byte[] outdata = new byte[44 + datalen];
				outdata[0] = 0x41;
				outdata[1] = 0x52;
				outdata[2] = 0x11;
				outdata[3] = 41;

				UInt32 epochnow = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
				outdata[4] = (byte) (epochnow >> 24);
				outdata[5] = (byte) (epochnow >> 16);
				outdata[6] = (byte) (epochnow >> 8);
				outdata[7] = (byte) (epochnow);
				Array.Copy(localAddress.GetAddressBytes(), 0, outdata, 8, 16);

				SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
				byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(password));

				int hashOffset = 8 + (outdata[0] >> 4)*4;
				Array.Copy(passwdHash, 0, outdata, hashOffset, 20);
				Array.Copy(data, 0, outdata, 44, datalen);

				byte[] ourHash = sha1.ComputeHash(outdata, 0, outdata.Length);
				Array.Copy(ourHash, 0, outdata, hashOffset, 20);

				_udpSocket.SendTo(outdata, endPoint);
			} else {
				_rawSocket.SendTo(data, endPoint);
			}
		}

		private void threadLoop() {
			byte[] data = new byte[2048];

			while (_running) {
				if (_type == TunnelType.AYIYAinIPv4) {
					while (_udpSocket.Poll(waitms*1000, SelectMode.SelectRead)) {
						EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.IPv6Any, 0);
						int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
						                                     SocketFlags.None,
						                                     ref sender);
						//Console.WriteLine("Received an AYIYA packet from {0}", sender);
						IPEndPoint endPoint = (IPEndPoint) sender;

						if (datalen < 8) {
							Console.WriteLine("Packet length {0} invalid", datalen);
							continue;
						}

						handleAyiyaPacket(endPoint, data, datalen);
					}
				} else if (_type == TunnelType.Heartbeat) {
					while (_udpSocket.Poll(waitms*1000, SelectMode.SelectRead)) {
						EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.Any, 0);
						int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
						                                     SocketFlags.None,
						                                     ref sender);
						Console.WriteLine("Received a heartbeat packet from {0}", sender);

						/* Nullify the port of the end point, otherwise it won't be found */
						IPEndPoint endPoint = new IPEndPoint(((IPEndPoint) sender).Address, 0);

						handleHeartbeatPacket(endPoint, data, datalen);
					}
				} else {
					if (!_rawSocket.WaitForReadable())
						continue;

					IPEndPoint endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
					int datalen = _rawSocket.ReceiveFrom(data, ref endPoint);
					Console.WriteLine("Received a packet from {0}", endPoint);

					_sessionManager.PacketFromInputDevice(data, 0, datalen);
				}
			}
		}

		private void handleHeartbeatPacket(IPEndPoint source, byte[] data, int datalen) {
			int strlen = datalen;
			for (int i=0; i<datalen; i++) {
				if (data[i] == 0) {
					strlen = i;
					break;
				} else if (data[i] < 32 || data[i] > 126) {
					Console.WriteLine("Heartbeat packet contains non-ascii characters");
					return;
				}
			}

			string str = Encoding.ASCII.GetString(data, 0, strlen);
			if (!str.StartsWith("HEARTBEAT TUNNEL ")) { 
				Console.WriteLine("Heartbeat string not found");
				return;
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
				Console.WriteLine("Error parsing heartbeat packet");
				return;
			}

			Console.WriteLine("Identifier: {0} Source: {1} Epochtime: {2}", identifier, sourceaddr, epochtime);

			/* Check for epoch time correctness */
			UInt32 epochnow = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;                     
			int epochdiff = (int) (epochnow - epochtime);
			if (epochdiff < 0)
				epochdiff = -epochdiff;
			if (epochdiff > CLOCK_MAX_OFFSET) {
				Console.WriteLine("The clock is too much off ({0} seconds)", epochdiff);                                  
				return;
			}

			Int64 tunnelId = _sessionManager.TunnelIdFromAddress(identifier);
			if (tunnelId < 0) {
				/* Invalid or timed out session */
				Console.WriteLine("Session for Heartbeat not found");
				return;
			}

			string theirHashStr = str.Substring(str.Length-32, 32);
			str = str.Substring(0, str.Length-32);
			str += _sessionManager.GetSessionPassword(tunnelId);

			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] ourHash = md5.ComputeHash(Encoding.ASCII.GetBytes(str));
			string ourHashStr = BitConverter.ToString(ourHash).Replace("-", "").ToLower();

			if (!theirHashStr.Equals(ourHashStr)) {
				Console.WriteLine("Incorrect Heartbeat hash");
				return;
			}

			_sessionManager.UpdateSession(identifier, source);
		}

		private void handleAyiyaPacket(IPEndPoint source, byte[] data, int datalen) {
			if ((data[0] != 0x11 && data[0] != 0x41) || // IDlen = 1 | 4, IDtype = int
			     data[1] != 0x52 || // siglen = 5, method = SHA1
			    // auth = sharedsecret, opcode = noop | forward | echo response
			    (data[2] != 0x10 && data[2] != 0x11 && data[2] != 0x14)) {
				return;
			}

			/* Start with the size of AYIYA header */
			int hlen = 8 + (data[0] >> 4)*4 + (data[1] >> 4)*4;
			if (datalen < hlen) {
				Console.WriteLine("AYIYA header length {0} invalid", datalen);
				return;
			}

			int length = hlen;
			if (data[3] == 4 && datalen >= hlen+20) { /* IPPROTO_IPIP */
				/* In case of IPv4, add the total length */
				length += data[length+2]*256 + data[length+3];
			} else if (data[3] == 41 && datalen >= hlen+40) { /* IPPROTO_IPV6 */
				/* In case of IPv6, add the header and payload lengths */
				length += 40 + data[length+4]*256 + data[length+5];
			} else if (data[3] == 59) { /* IPPROTO_NONE */
				/* In case of no content, opcode should be nop or echo response */
				if ((data[2] & 0x0f) != 0 && (data[2] & 0x0f) != 4) {
					return;
				}
			} else {
				Console.WriteLine("Invalid next header in AYIYA packet: " + data[3]);
				return;
			}

			/* Check for epoch time correctness */
			UInt32 epochtime = (UInt32) ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
			UInt32 epochnow = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
			int epochdiff = (int) (epochnow - epochtime);
			if (epochdiff < 0)
				epochdiff = -epochdiff;
			if (epochdiff > CLOCK_MAX_OFFSET) {
				Console.WriteLine("The clock is too much off ({0} seconds)", epochdiff);
				return;
			}

			/* Extract the identifier part from AYIYA header */
			byte[] ipaddr = new byte[((data[0] >> 4) == 1) ? 4 : 16];
			Array.Copy(data, 8, ipaddr, 0, ipaddr.Length);
			IPAddress identifier = new IPAddress(ipaddr);

			Int64 tunnelId = _sessionManager.TunnelIdFromAddress(identifier);
			if (tunnelId < 0) {
				/* Invalid or timed out session */
				Console.WriteLine("Session for AYIYA not found");
				return;
			}

			SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
			string passwd = _sessionManager.GetSessionPassword(tunnelId);
			byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(passwd));

			/* Replace the hash with password hash */
			byte[] theirHash = new byte[20];
			int hashOffset = 8 + (data[0] >> 4)*4;
			Array.Copy(data, hashOffset, theirHash, 0, 20);
			Array.Copy(passwdHash, 0, data, hashOffset, 20);

			byte[] ourHash = sha1.ComputeHash(data, 0, length);
			if (!BitConverter.ToString(ourHash).Equals(BitConverter.ToString(theirHash))) {
				Console.WriteLine("Incorrect AYIYA hash");
				return;
			}
			_sessionManager.UpdateSession(identifier, source);

			/* In case of NOP act like it would be a heartbeat */
			if ((data[2] & 0x0f) == 0) {
				return;
			}

			_sessionManager.PacketFromInputDevice(data, hlen, datalen-hlen);
		}
	}
}
