/* NABLA - Automatic IP Tunneling and Connectivity
 * Copyright (C) 2009  Juho Vähä-Herttua
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Threading;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Nabla.Sockets;

namespace Nabla {
	public class Server {
		private Thread _intThread;
		private Thread _extThread;

		private byte[] _intHWAddress;
		private byte[] _extHWAddress;

		private RawSocket _intSocket;
		private RawSocket _extSocket;
		private NATMapper _mapper;

		public Server(RawSocket intSocket, RawSocket extSocket) {
			_intSocket = intSocket;
			_extSocket = extSocket;

			_intHWAddress = RawSocket.GetHardwareAddress("eth0");
			_extHWAddress = RawSocket.GetHardwareAddress("eth0");

			List<IPAddress> addressList = new List<IPAddress>();
			addressList.Add(IPAddress.Parse("59.64.158.119"));

			_mapper = new NATMapper(addressList.ToArray());
			_mapper.AddProtocol(ProtocolType.Tcp);
			_mapper.AddProtocol(ProtocolType.Udp);
			_mapper.AddProtocol(ProtocolType.Icmp);
		}

		public void Start() {
			_intThread = new Thread(new ThreadStart(this.intLoop));
			_extThread = new Thread(new ThreadStart(this.extLoop));
		}

		public void Stop() {
		}

		private void intLoop() {
			byte[] data = new byte[2048];

			while (true) {
				if (!_intSocket.WaitForReadable())
					continue;

				int datalen = _intSocket.Receive(data);
				if ((data[12] << 8 | data[13]) != 0x86dd)
					continue;

				/* These assume that it's an IPv4-in-IPv6 packet */
				byte[] gateway = new byte[6];
				Array.Copy(data, 6, gateway, 0, 6);

				byte[] publicIP = new byte[16];
				Array.Copy(data, 14+8, publicIP, 0, 16);

				NATPacket packet = new NATPacket(data, 54, data.Length-54);
				if (!packet.Supported)
					continue;

				Console.WriteLine("Protocol type {0}, NAT identifier {0}",
				                  packet.ProtocolType, packet.GetNatID(false));

				NATMapping m = _mapper.GetIntMapping(packet.ProtocolType,
				                                     packet.SourceAddress,
				                                     packet.GetNatID(false));

				if (m == null) {
					Console.WriteLine("Unmapped connection, add mapping");

					m = new NATMapping(packet.ProtocolType, gateway,
					                   new IPAddress(publicIP),
					                   packet.SourceAddress,
					                   packet.GetNatID(false));
					_mapper.AddMapping(m);
				}

				Console.WriteLine("Using external IP {0} with port {1} (0x{1:x})",
				                  m.ExternalAddress, m.ExternalPort);

				packet.SourceAddress = m.ExternalAddress;
				packet.SetNatID(m.ExternalPort, false);

				/* Copy the Ethernet header values */
				Array.Copy(m.ExternalGateway, 0, data, 0, 6);
				Array.Copy(_extHWAddress, 0, data, 6, 6);
				data[12] = 0x08;
				data[13] = 0x00;

				/* Overwrite the packet data */
				Array.Copy(packet.Bytes, 0, data, 14, packet.Bytes.Length);

				_extSocket.Send(data, packet.Bytes.Length+14);
			}
		}

		private void extLoop() {
		}

		private static void Main(string[] args) {
			if (args.Length != 2) {
				Console.WriteLine("Invalid number of arguments\n");
				return;
			}

			RawSocket intSocket = RawSocket.GetRawSocket(args[0], AddressFamily.DataLink, 0x86dd, 100);
			RawSocket extSocket = RawSocket.GetRawSocket(args[1], AddressFamily.DataLink, 0x0800, 100);

			Server server = new Server(intSocket, extSocket);
			server.Start();
		}
	}
}
