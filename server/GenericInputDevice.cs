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
	public enum GenericInputType {
		Ayiya,
		Heartbeat,
		IPv4inIPv4,
		IPv4inIPv6,
		IPv6inIPv4,
		IPv6inIPv6
	}

	public class GenericInputDevice : InputDevice {
		private const int waitms = 100;

		private Thread _thread;
		private volatile bool _running;

		private SessionManager _sessionManager;

		private Socket _udpSocket = null;
		private RawSocket _rawSocket = null;

		private GenericInputType _type;
		private List<TunnelType> _tunnelTypes = new List<TunnelType>();

		public GenericInputDevice(string deviceName, GenericInputType type) {
			_type = type;

			AddressFamily addressFamily = AddressFamily.Unknown;
			int protocol = 0;

			switch (type) {
			case GenericInputType.Ayiya:
				_udpSocket = new Socket(AddressFamily.InterNetworkV6,
				                        SocketType.Dgram,
				                        ProtocolType.Udp);
				_udpSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, 5072));
				_tunnelTypes.Add(TunnelType.AyiyaIPv4inIPv4);
				_tunnelTypes.Add(TunnelType.AyiyaIPv4inIPv6);
				_tunnelTypes.Add(TunnelType.AyiyaIPv6inIPv4);
				_tunnelTypes.Add(TunnelType.AyiyaIPv6inIPv6);
				break;
			case GenericInputType.Heartbeat:
				/* We still need a raw socket for Heartbeat */
				addressFamily = AddressFamily.InterNetwork;
				protocol = 41;

				_udpSocket = new Socket(AddressFamily.InterNetwork,
				                        SocketType.Dgram,
				                        ProtocolType.Udp);
				_udpSocket.Bind(new IPEndPoint(IPAddress.Any, 3740));
				_tunnelTypes.Add(TunnelType.Heartbeat);
				break;
			case GenericInputType.IPv4inIPv4:
				addressFamily = AddressFamily.InterNetwork;
				protocol = 4;
				_tunnelTypes.Add(TunnelType.IPv4inIPv4);
				break;
			case GenericInputType.IPv4inIPv6:
				addressFamily = AddressFamily.InterNetworkV6;
				protocol = 4;
				_tunnelTypes.Add(TunnelType.IPv4inIPv6);
				break;
			case GenericInputType.IPv6inIPv4:
				addressFamily = AddressFamily.InterNetwork;
				protocol = 41;
				_tunnelTypes.Add(TunnelType.IPv6inIPv4);
				break;
			case GenericInputType.IPv6inIPv6:
				addressFamily = AddressFamily.InterNetworkV6;
				protocol = 41;
				_tunnelTypes.Add(TunnelType.IPv6inIPv6);
				break;
			default:
				throw new Exception("Unsupported input type: " + type);
			}

			if (addressFamily != AddressFamily.Unknown) {
				_rawSocket = RawSocket.GetRawSocket(deviceName, addressFamily, protocol, waitms);
			}

			_thread = new Thread(new ThreadStart(this.threadLoop));
		}

		public void SetSessionManager(SessionManager sessionManager) {
			_sessionManager = sessionManager;
		}

		public TunnelType[] GetSupportedTypes() {
			return _tunnelTypes.ToArray();
		}

		public void Start() {
			_running = true;
			_thread.Start();
		}

		public void Stop() {
			_running = false;
			_thread.Join();
		}

		public void SendPacket(TunnelSession session, byte[] data) {
			if (_type == GenericInputType.Ayiya) {
				/* FIXME: not necessarily IPv6 */
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
				Array.Copy(session.PrivateAddress.GetAddressBytes(), 0, outdata, 8, 16);
				/* FIXME: needs POP address */
				outdata[23] = 0;

				SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
				byte[] passwdHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(session.Password));

				int hashOffset = 8 + (outdata[0] >> 4)*4;
				Array.Copy(passwdHash, 0, outdata, hashOffset, 20);
				Array.Copy(data, 0, outdata, 44, datalen);

				byte[] ourHash = sha1.ComputeHash(outdata, 0, outdata.Length);
				Array.Copy(ourHash, 0, outdata, hashOffset, 20);

				_udpSocket.SendTo(outdata, session.EndPoint);
			} else {
				_rawSocket.SendTo(data, session.EndPoint);
			}
		}

		private void threadLoop() {
			byte[] data = new byte[2048];

			while (_running) {
				if (_type == GenericInputType.Ayiya) {
					while (_udpSocket.Poll(waitms*1000, SelectMode.SelectRead)) {
						EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.IPv6Any, 0);
						int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
						                                     SocketFlags.None,
						                                     ref sender);
						Console.WriteLine("Received an AYIYA packet from {0}", sender);
						IPEndPoint endPoint = (IPEndPoint) sender;

						if (datalen < 8) {
							Console.WriteLine("Packet length {0} invalid", datalen);
							continue;
						}

						int hlen = 8 + (data[0] >> 4)*4 + (data[1] >> 4)*4;
						if (datalen < hlen) {
							Console.WriteLine("AYIYA header length {0} invalid", datalen);
							continue;
						}

						/* FIXME: in case of 59 internal protocol not known */
						if (data[3] != 4 && data[3] != 41 && data[3] == 59) {
							Console.WriteLine("AYIYA next header unknown: " + data[3]);
							continue;
						}

						/* XXX: Ugly way to detect if the source is IPv4 */
						byte[] sourceBytes = endPoint.Address.GetAddressBytes();
						sourceBytes[12] = sourceBytes[13] = sourceBytes[14] = sourceBytes[15] = 0;
						bool sourceIsIPv4 = IPAddress.Parse("::ffff:0.0.0.0").Equals(new IPAddress(sourceBytes));

						TunnelType tunnelType;
						if (sourceIsIPv4) {
							if (data[3] == 4) {
								tunnelType = TunnelType.AyiyaIPv4inIPv4;
							} else {
								tunnelType = TunnelType.AyiyaIPv6inIPv4;
							}
						} else {
							if (data[3] == 4) {
								tunnelType = TunnelType.AyiyaIPv4inIPv6;
							} else {
								tunnelType = TunnelType.AyiyaIPv6inIPv6;
							}
						}

						/* If not from a valid session, ignore the packet */
						if (!_sessionManager.UpdateSession(tunnelType, endPoint, data)) {
							continue;
						}

						if (!_sessionManager.SessionAlive(tunnelType, endPoint))
							continue;

						/* Remove the AYIYA header from the packet */
						byte[] outdata = new byte[datalen-hlen];
						Array.Copy(data, hlen, outdata, 0, outdata.Length);

						_sessionManager.ProcessPacket(tunnelType, endPoint, outdata);
					}
				} else {
					IPEndPoint endPoint;
					int datalen;

					if (_type == GenericInputType.Heartbeat) {
						while (_udpSocket.Poll(0, SelectMode.SelectRead)) {
							EndPoint sender = (EndPoint) new IPEndPoint(IPAddress.Any, 0);
							datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
							                                 SocketFlags.None,
							                                 ref sender);
							Console.WriteLine("Received a heartbeat packet from {0}", sender);

							/* Nullify the port of the end point, otherwise it won't be found */
							endPoint = new IPEndPoint(((IPEndPoint) sender).Address, 0);

							/* Make sure that the heartbeat packet is null-terminated */
							data[datalen] = 0;

							/* Possibly update the session source IP if changed */
							if (!_sessionManager.UpdateSession(TunnelType.Heartbeat, endPoint, data)) {
								Console.WriteLine("Heartbeat packet invalid, discarded");
							}
						}
					}

					if (!_rawSocket.WaitForReadable())
						continue;

					TunnelType tunnelType;
					switch (_type) {
					case GenericInputType.IPv4inIPv4:
						tunnelType = TunnelType.IPv4inIPv4;
						break;
					case GenericInputType.IPv6inIPv4:
						tunnelType = TunnelType.IPv6inIPv4;
						break;
					case GenericInputType.IPv4inIPv6:
						tunnelType = TunnelType.IPv4inIPv6;
						break;
					case GenericInputType.IPv6inIPv6:
						tunnelType = TunnelType.IPv6inIPv6;
						break;
					case GenericInputType.Heartbeat:
						tunnelType = TunnelType.Heartbeat;
						break;
					default:
						throw new Exception("Unsupported input type: " + _type);
					}

					endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);;
					datalen = _rawSocket.ReceiveFrom(data, ref endPoint);
					Console.WriteLine("Received a packet from {0}", endPoint);

					if (!_sessionManager.SessionAlive(tunnelType, endPoint))
						continue;

					byte[] outdata = new byte[datalen];
					Array.Copy(data, 0, outdata, 0, datalen);

					_sessionManager.ProcessPacket(tunnelType, endPoint, outdata);
				}
			}
		}
	}
}
