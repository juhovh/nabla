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
	public class Server {
		private Thread _intThread;

		private RawSocket _intSocket;
		private ParallelDevice _extDevice;
		private NATMapper _mapper;

		public Server(RawSocket intSocket, ParallelDevice extDevice) {
			_intSocket = intSocket;
			_extDevice = extDevice;

			extDevice.ReceivePacketCallback = new ReceivePacketCallback(extReceive);
			extDevice.IPv4Route = new IPConfig(IPAddress.Parse("192.168.1.0"), 24, IPAddress.Parse("192.168.1.1"));
			extDevice.AddSubnet(IPAddress.Parse("192.168.1.16"), 28);

			List<IPAddress> addressList = new List<IPAddress>();
			addressList.Add(IPAddress.Parse("192.168.1.16"));

			_mapper = new NATMapper(addressList.ToArray());
			_mapper.AddProtocol(ProtocolType.Tcp);
			_mapper.AddProtocol(ProtocolType.Udp);
			_mapper.AddProtocol(ProtocolType.Icmp);
		}

		public void Start() {
			_intThread = new Thread(new ThreadStart(this.intLoop));
			_intThread.Start();

			_extDevice.Start();
		}

		public void Stop() {
		}

		private void intLoop() {
			byte[] data = new byte[2048];

			while (true) {
				if (!_intSocket.WaitForReadable())
					continue;

				IPEndPoint endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
				int datalen = _intSocket.ReceiveFrom(data, ref endPoint);
				Console.WriteLine("Received a packet from {0}", endPoint);

				NATPacket packet;
				try {
					packet = new NATPacket(data, datalen);
				} catch (Exception) {
					/* Packet not supported by NATPacket */
					continue;
				}

				Console.WriteLine("Protocol type {0}, NAT identifier {0}",
				                  packet.ProtocolType, packet.GetNatID(false));

				NATMapping m = _mapper.GetIntMapping(packet.ProtocolType,
				                                     packet.SourceAddress,
				                                     packet.GetNatID(false));

				if (m == null) {
					Console.WriteLine("Unmapped connection, add mapping");

					m = new NATMapping(packet.ProtocolType,
					                   endPoint.Address,
					                   packet.SourceAddress,
					                   packet.GetNatID(false));
					_mapper.AddMapping(m);
				}

				Console.WriteLine("Using external IP {0} with ID {1} (0x{1:x})",
				                  m.ExternalAddress, m.ExternalID);

				packet.SourceAddress = m.ExternalAddress;
				packet.SetNatID(m.ExternalID, false);

				_extDevice.SendPacket(packet.Bytes);
			}
		}

		private void extReceive(byte[] data) {
			byte[] gateway = new byte[6];
			Array.Copy(data, 6, gateway, 0, 6);

			/* This assumes that it's an IPv4 packet in Ethernet frame */
			NATPacket packet;
			try {
				packet = new NATPacket(data);
			} catch (Exception) {
				/* Packet not supported by NATPacket */
				return;
			}

			Console.WriteLine("Protocol type {0}, NAT identifier {0}",
			packet.ProtocolType, packet.GetNatID(true));

			NATMapping m = _mapper.GetExtMapping(packet.ProtocolType,
							     packet.GetNatID(true));
			if (m == null) {
				Console.WriteLine("Unmapped connection, drop packet");
				return;
			}

			Console.WriteLine("Using external IP {0} with port {1} (0x{1:x})",
					  m.ExternalAddress, m.ExternalID);

			packet.DestinationAddress = m.ClientPrivateAddress;
			packet.SetNatID(m.ClientID, true);

			IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse("::1"), 0);
			_intSocket.SendTo(packet.Bytes, endPoint);
		}

		private static void Main(string[] args) {
			if (args.Length != 2) {
				Console.WriteLine("Invalid number of arguments\n");
				return;
			}

			RawSocket intSocket = RawSocket.GetRawSocket(args[0], AddressFamily.InterNetworkV6, 4, 100);
			ParallelDevice extDevice = new ParallelDevice(args[1]);

			Server server = new Server(intSocket, extDevice);
			server.Start();

			while (true) {
				Thread.Sleep(1000);
			}
		}
	}
}
