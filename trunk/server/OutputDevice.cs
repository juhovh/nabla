/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009-2010  Juho Vähä-Herttua
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
	public delegate void OutputDeviceCallback(byte[] data, int offset, int length);

	public class OutputDevice {
		private ParallelDevice _device;
		private NATMapper _mapper = new NATMapper();
		private OutputDeviceCallback _callback;

		public IPAddress IPv6LocalAddress = null;

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
				byte[] hwaddress = _device.HardwareAddress;

				/* FIXME: These bytes should be reserved for a application
				 *        specific byte, instance specific byte and tunnel
				 *        specific byte, it's gonna be tight around here... */

				/* Also see the RFC 4291 about the universal/local bit, in this
				 * case the 7th bit should be zero since we administer the
				 * addresses locally */
				ipv6Bytes[8]  = 0x18;
				ipv6Bytes[9]  = 0x37;

				/* These three bytes should be reserved for the tunnel number */
				ipv6Bytes[10] = 0x00;
				ipv6Bytes[11] = 0x00;
				ipv6Bytes[12] = 0x00;

				/* These three bytes should be the same as hardware address */
				ipv6Bytes[13] = 0x00;
				ipv6Bytes[14] = 0x00;
				ipv6Bytes[15] = 0x00;

				ipv6 = new IPAddress(ipv6Bytes);
				_device.AddSubnet(ipv6, 80);

				Array.Copy(hwaddress, hwaddress.Length - 3, ipv6Bytes, 13, 3);
				ipv6 = new IPAddress(ipv6Bytes);
				IPv6LocalAddress = ipv6;

				Console.WriteLine("Added IPv6 subnet: {0}/{1}", ipv6, 104);
			}
		}

		public void Start() {
			_device.Start();
		}

		public void Stop() {
			_device.Stop();
		}

		public void SendPacket(byte[] data) {
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
			}

			/* FIXME: Catch exceptions */
			_device.SendPacket(data);
		}

		private void receivePacket(byte[] data) {
			AddressFamily addressFamily = getPacketFamily(data);
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

				data = packet.Bytes;
			}

			_callback(data, 0, data.Length);
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
