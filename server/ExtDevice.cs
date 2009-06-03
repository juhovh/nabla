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
	public delegate void ExtDeviceCallback(AddressFamily family, IPEndPoint destination, byte[] data);

	public class ExtDevice {
		private ParallelDevice _device;
		private NATMapper _mapper;
		private ExtDeviceCallback _callback;

		public ExtDevice(string deviceName, ExtDeviceCallback cb) {
			_device = new ParallelDevice(deviceName);
			_device.ReceivePacketCallback = new ReceivePacketCallback(receivePacket);
			_mapper = new NATMapper();
			_mapper.AddProtocol(ProtocolType.Tcp);
			_mapper.AddProtocol(ProtocolType.Udp);
			_mapper.AddProtocol(ProtocolType.Icmp);
			_callback = cb;

			/* FIXME: These values shouldn't be hardcoded */
			_device.IPv4Route = new IPConfig(IPAddress.Parse("192.168.1.0"), 24, IPAddress.Parse("192.168.1.1"));
			_device.AddSubnet(IPAddress.Parse("192.168.1.16"), 28);
			_mapper.Addresses += IPAddress.Parse("192.168.1.16");
		}

		public void Start() {
			_device.Start();
		}

		public void Stop() {
			_device.Stop();
		}

		public void SendPacket(IPEndPoint source, byte[] data) {
			AddressFamily addressFamily = getPacketFamily(data);

			if (addressFamily == AddressFamily.InterNetwork) {
				NATPacket packet;
				try {
					packet = new NATPacket(data);
				} catch (Exception) {
					/* Packet not supported by NATPacket */
					return;
				}

				Console.WriteLine("Protocol type {0}, NAT identifier {0}",
				                  packet.ProtocolType, packet.IntNatID);

				NATMapping m = _mapper.GetIntMapping(packet.ProtocolType,
				                                     packet.SourceAddress,
				                                     packet.IntNatID);

				if (m == null) {
					Console.WriteLine("Unmapped connection, add mapping");
					m = new NATMapping(packet.ProtocolType,
					                   source,
					                   packet.SourceAddress,
					                   packet.IntNatID);
					_mapper.AddMapping(m);
				}

				Console.WriteLine("Using external IP {0} with ID {1} (0x{1:x})",
				                  m.ExternalAddress, m.ExternalID);

				/* Convert the source values to the public ones */
				packet.SourceAddress = m.ExternalAddress;
				packet.IntNatID = m.ExternalID;

				/* Override the original data packet */
			}

			/* FIXME: Catch exceptions */
			_device.SendPacket(data);
		}

		private void receivePacket(byte[] data) {
			AddressFamily addressFamily = getPacketFamily(data);

			IPEndPoint destination;
			if (addressFamily == AddressFamily.InterNetwork) {
				NATPacket packet;
				try {
					packet = new NATPacket(data);
				} catch (Exception) {
					/* Packet not supported by NATPacket */
					return;
				}

				Console.WriteLine("Protocol type {0}, NAT identifier {0}",
				                  packet.ProtocolType, packet.ExtNatID);

				NATMapping m = _mapper.GetExtMapping(packet.ProtocolType,
				                                     packet.ExtNatID);

				if (m == null) {
					Console.WriteLine("Unmapped connection, drop packet");
					return;
				}

				Console.WriteLine("Received external IP {0} with port {1} (0x{1:x})",
				                  m.ExternalAddress, m.ExternalID);

				/* Convert the destination values to the local ones */
				packet.DestinationAddress = m.InternalAddress;
				packet.ExtNatID = m.InternalID;

				destination = m.ClientEndPoint;
				data = packet.Bytes;
			} else {
				byte[] ipaddress = new byte[16];
				int port = 0;

				Array.Copy(data, 24, ipaddress, 0, 16);
				ProtocolType type = (ProtocolType) data[6];
				if (type == ProtocolType.Udp || type == ProtocolType.Tcp) {
					port = (data[42] << 8) | data[43];
				}

				destination = new IPEndPoint(new IPAddress(ipaddress), port);
			}

			_callback(addressFamily, destination, data);
		}

		private AddressFamily getPacketFamily(byte[] data) {
			switch (data[0] >> 4) {
			case 4:
				return AddressFamily.InterNetwork;
			case 6:
				return AddressFamily.InterNetworkV6;
			default:
				/* Unknown or invalid packet, shouldn't happen */
				throw new Exception("Unknown address family");
			}
		}
	}
}
