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
		private NATMapper _mapper = new NATMapper();
		private Dictionary<IPAddress, IPEndPoint> _ipv6map = new Dictionary<IPAddress, IPEndPoint>();
		private ExtDeviceCallback _callback;

		public ExtDevice(string deviceName, ExtDeviceCallback cb) {
			_device = new ParallelDevice(deviceName);
			_device.ReceivePacketCallback = new ReceivePacketCallback(receivePacket);
			_mapper.AddProtocol(ProtocolType.Tcp);
			_mapper.AddProtocol(ProtocolType.Udp);
			_mapper.AddProtocol(ProtocolType.Icmp);
			_callback = cb;

			/* FIXME: These values shouldn't be hardcoded */
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
				data = packet.Bytes;
			} else {
				byte[] ipaddress = new byte[16];
				Array.Copy(data, 8, ipaddress, 0, 16);
				IPAddress addr = new IPAddress(ipaddress);
				if (!_ipv6map.ContainsKey(addr)) {
					_ipv6map.Add(addr, source);
				}
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

				NATMapping m = _mapper.GetExtMapping(packet.ProtocolType,
				                                     packet.ExtNatID);

				if (m == null) {
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
				Array.Copy(data, 24, ipaddress, 0, 16);
				IPAddress addr = new IPAddress(ipaddress);

				if (!_ipv6map.ContainsKey(addr)) {
					Console.WriteLine("Unmapped IPv6 connection, drop packet");
					return;
				}

				destination = _ipv6map[addr];
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
