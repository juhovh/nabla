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
	public delegate void OutputDeviceCallback(AddressFamily family, IPEndPoint destination, byte[] data);

	public class OutputDevice {
		private ParallelDevice _device;
		private NATMapper _mapper = new NATMapper();
		private Dictionary<IPAddress, IPEndPoint> _ipv6map = new Dictionary<IPAddress, IPEndPoint>();
		private OutputDeviceCallback _callback;

		public IPAddress IPv6TunnelPrefix = null;

		public OutputDevice(string deviceName, bool enableIPv4, bool enableIPv6, OutputDeviceCallback cb) {
			_device = new ParallelDevice(deviceName);
			_device.ReceivePacketCallback = new ReceivePacketCallback(receivePacket);
			_mapper.AddProtocol(ProtocolType.Tcp);
			_mapper.AddProtocol(ProtocolType.Udp);
			_mapper.AddProtocol(ProtocolType.Icmp);
			_callback = cb;

			DateTime confStart = DateTime.Now;
			bool confSuccess = _device.AutoConfigureRoutes(enableIPv4, enableIPv6, 2000);
			Console.WriteLine("Configure took timespan: " + (DateTime.Now - confStart));
			Console.WriteLine("Configure success was: " + confSuccess);

			if (_device.IPv4Route != null) {
				IPConfig route = _device.IPv4Route;
				IPAddress ipv4 = _device.IPv4Route.Address;
				byte[] ipv4Bytes = ipv4.GetAddressBytes();

				/* FIXME: This bruteforce is ugly, but works for most cases */
				bool addressFound = false;
				for (byte i=1; i<255; i++) {
					ipv4Bytes[3] = i;
					ipv4 = new IPAddress(ipv4Bytes);

					if (!route.AddressInSubnet(ipv4))
						continue;

					if (!_device.ProbeIPAddress(ipv4)) {
						addressFound = true;
						break;
					}
				}

				if (!addressFound) {
					throw new Exception("Could not find an available IPv4 address");
				}

				_device.AddSubnet(ipv4, 32);
				_mapper.Addresses += ipv4;
				Console.WriteLine("Added IPv4 address: {0}", ipv4);
			}

			if (_device.IPv6Route != null) {
				IPAddress ipv6 = _device.IPv6Route.Address;
				byte[] ipv6Bytes = ipv6.GetAddressBytes();

				/* FIXME: These bytes should be reserved for a application
				 *        specific byte, instance specific byte and tunnel
				 *        specific byte, it's gonna be tight around here... */

				/* Also see the RFC 4291 about the universal/local bit, in this
				 * case the 7th bit should be zero since we administer the
				 * addresses locally */
				ipv6Bytes[8]  = 0x00;
				ipv6Bytes[9]  = 0x00;
				ipv6Bytes[10] = 0x00;
				ipv6Bytes[11] = 0x00;
				ipv6Bytes[12] = 0x00;

				ipv6 = new IPAddress(ipv6Bytes);

				_device.AddSubnet(ipv6, 104);
				IPv6TunnelPrefix = ipv6;
				Console.WriteLine("Added IPv6 subnet: {0}/{1}", ipv6, 104);
			}
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
				/* Get the source address of the IPv6 packet */
				byte[] ipaddress = new byte[16];
				Array.Copy(data, 8, ipaddress, 0, 16);
				IPAddress addr = new IPAddress(ipaddress);

				/* If the source IPv6 address is not found from the mapping,
				 * map it to the source endpoint (tunnel endpoint) correctly */
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
				/* Get the destination address of the packet */
				byte[] ipaddress = new byte[16];
				Array.Copy(data, 24, ipaddress, 0, 16);
				IPAddress addr = new IPAddress(ipaddress);

				/* If the packet is sent to an unknown IPv6 destination, simply
				 * drop the packet from sending data. */
				// FIXME: Should handle multicast
				if (!_ipv6map.ContainsKey(addr)) {
					return;
				}

				/* Get the (tunnel) endpoint from mapping */
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
