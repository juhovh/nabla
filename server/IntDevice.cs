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
		private Thread _thread;
		private volatile bool _running;

		private RawSocket _socket;
		private TunnelType _type;
		private IntDeviceCallback _callback;

		public IntDevice(string deviceName, TunnelType type, IntDeviceCallback cb) {
			if (type == TunnelType.Ayiya) {
				throw new Exception("AYIYA not supported yet");
			} else {
				AddressFamily addressFamily;
				int protocol;

				if (type == TunnelType.IPv4inIPv4) {
					addressFamily = AddressFamily.InterNetwork;
					protocol = 4;
				} else if (type == TunnelType.IPv4inIPv6) {
					addressFamily = AddressFamily.InterNetworkV6;
					protocol = 4;
				} else if (type == TunnelType.IPv6inIPv4) {
					addressFamily = AddressFamily.InterNetwork;
					protocol = 41;
				} else if (type == TunnelType.IPv6inIPv6) {
					addressFamily = AddressFamily.InterNetworkV6;
					protocol = 41;
				} else {
					throw new Exception("Unsupported tunnel type: " + type);
				}

				_socket = RawSocket.GetRawSocket(deviceName, addressFamily, protocol, 100);
			}
			_callback = cb;

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
			_socket.Send(data);
		}

		private void threadLoop() {
			byte[] data = new byte[2048];

			while (_running) {
				if (!_socket.WaitForReadable())
					continue;

				IPEndPoint endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
				int datalen = _socket.ReceiveFrom(data, ref endPoint);
				Console.WriteLine("Received a packet from {0}", endPoint);

				byte[] outdata = new byte[datalen];
				Array.Copy(data, 0, outdata, 0, datalen);
				_callback(_type, endPoint, outdata);
			}
		}
	}
}
