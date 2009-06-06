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
using Nabla.Sockets;

namespace Nabla {
	public delegate void IntDeviceCallback(TunnelType type, IPEndPoint source, byte[] data);

	public class IntDevice {
		private const int waitms = 100;

		private Thread _thread;
		private volatile bool _running;

		private SessionManager _sessionManager;
		private IntDeviceCallback _callback;

		private Socket _udpSocket = null;
		private RawSocket _rawSocket = null;

		public readonly TunnelType TunnelType;

		public IntDevice(SessionManager sessionManager, string deviceName, TunnelType type, IntDeviceCallback cb) {
			_sessionManager = sessionManager;
			TunnelType = type;
			_callback = cb;

			AddressFamily addressFamily = AddressFamily.Unknown;
			int protocol = 0;

			switch (type) {
			case TunnelType.AyiyaIPv4inIPv4:
			case TunnelType.AyiyaIPv4inIPv6:
			case TunnelType.AyiyaIPv6inIPv4:
			case TunnelType.AyiyaIPv6inIPv6:
				if (type == TunnelType.AyiyaIPv4inIPv4 || type == TunnelType.AyiyaIPv6inIPv4) {
					_udpSocket = new Socket(AddressFamily.InterNetwork,
								SocketType.Dgram,
								ProtocolType.Udp);
					_udpSocket.Bind(new IPEndPoint(IPAddress.Any, 5072));
				} else {
					_udpSocket = new Socket(AddressFamily.InterNetworkV6,
								SocketType.Dgram,
								ProtocolType.Udp);
					_udpSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, 5072));
				}
				break;
			case TunnelType.Heartbeat:
				/* We still need a raw socket for Heartbeat */
				addressFamily = AddressFamily.InterNetwork;
				protocol = 41;

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
				throw new Exception("Unsupported tunnel type: " + type);
			}

			if (addressFamily != AddressFamily.Unknown) {
				_rawSocket = RawSocket.GetRawSocket(deviceName, addressFamily, protocol, waitms);
			}

			_thread = new Thread(new ThreadStart(this.threadLoop));
		}

		public void Start() {
			_running = true;
			_thread.Start();
		}

		public void Stop() {
			_running = false;
			_thread.Join();
		}

		public void SendPacket(IPEndPoint destination, byte[] data) {
			_rawSocket.Send(data);
		}

		private void threadLoop() {
			byte[] data = new byte[2048];

			while (_running) {
				if (TunnelType == TunnelType.AyiyaIPv4inIPv4 ||
				    TunnelType == TunnelType.AyiyaIPv4inIPv6 ||
				    TunnelType == TunnelType.AyiyaIPv6inIPv4 ||
				    TunnelType == TunnelType.AyiyaIPv6inIPv6) {
					while (_udpSocket.Poll(waitms*1000, SelectMode.SelectRead)) {
						IPEndPoint endPoint;
						if (TunnelType == TunnelType.AyiyaIPv4inIPv4 ||
						    TunnelType == TunnelType.AyiyaIPv6inIPv4) {
							endPoint = new IPEndPoint(IPAddress.Any, 0);
						} else {
							endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
						}

						EndPoint sender = (EndPoint) endPoint;
						int datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
						                                     SocketFlags.None,
						                                     ref sender);
						Console.WriteLine("Received an AYIYA packet from {0}", sender);

						if (datalen < 8 || datalen < (8 + (data[0] >> 4)*4 + (data[1] >> 4)*4)) {
							Console.WriteLine("Packet length {0} invalid", datalen);
							continue;
						}

						/* If not from a valid session, ignore the packet */
						if (!_sessionManager.UpdateSession(TunnelType, endPoint, data)) {
							continue;
						}

						if (!_sessionManager.SessionAlive(TunnelType, endPoint))
							continue;

						/* Remove the AYIYA header from the packet */
						int hlen = 4 + (data[0] >> 4)*4 + (data[1] >> 4)*4;
						byte[] outdata = new byte[datalen-hlen];
						Array.Copy(data, hlen, outdata, 0, outdata.Length);

						_callback(TunnelType, endPoint, outdata);
					}
				} else {
					IPEndPoint endPoint;
					int datalen;

					if (TunnelType == TunnelType.Heartbeat) {
						while (_udpSocket.Poll(0, SelectMode.SelectRead)) {
							endPoint = new IPEndPoint(IPAddress.Any, 0);
							EndPoint sender = (EndPoint) endPoint;
							datalen = _udpSocket.ReceiveFrom(data, 0, data.Length,
							                                 SocketFlags.None,
							                                 ref sender);
							Console.WriteLine("Received a heartbeat packet from {0}", sender);

							/* Nullify the port of the end point, otherwise it won't be found */
							endPoint = new IPEndPoint(((IPEndPoint) sender).Address, 0);

							/* Make sure that the heartbeat packet is null-terminated */
							data[datalen] = 0;

							/* Possibly update the session source IP if changed */
							if (!_sessionManager.UpdateSession(TunnelType, endPoint, data)) {
								Console.WriteLine("Heartbeat packet invalid, discarded");
							}
						}
					}

					if (!_rawSocket.WaitForReadable())
						continue;

					switch (TunnelType) {
					case TunnelType.IPv4inIPv4:
					case TunnelType.IPv6inIPv4:
					case TunnelType.Heartbeat:
						endPoint = new IPEndPoint(IPAddress.Any, 0);
						break;
					case TunnelType.IPv4inIPv6:
					case TunnelType.IPv6inIPv6:
						endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
						break;
					default:
						throw new Exception("Unsupported tunnel type: " + TunnelType);
					}
					datalen = _rawSocket.ReceiveFrom(data, ref endPoint);
					Console.WriteLine("Received a packet from {0}", endPoint);

					if (!_sessionManager.SessionAlive(TunnelType, endPoint))
						continue;

					byte[] outdata = new byte[datalen];
					Array.Copy(data, 0, outdata, 0, datalen);

					_callback(TunnelType, endPoint, outdata);
				}
			}
		}
	}
}
