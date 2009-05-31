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
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using Nabla.Sockets;

namespace Nabla {
	public class ParallelDevice {
		byte[] _hwaddr;
		RawSocket _socket;
		Thread _thread;

		Dictionary<IPAddress, int> _subnets
			= new Dictionary<IPAddress, int>();

		Dictionary<IPAddress, byte[]> _arptable
			= new Dictionary<IPAddress, byte[]>();

		public ParallelDevice(string deviceName) {
			_hwaddr = RawSocket.GetHardwareAddress(deviceName);
			_socket = RawSocket.GetRawSocket(deviceName,
			                                 AddressFamily.DataLink,
			                                 0, 100);
			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start() {
			AddSubnet(IPAddress.Parse("192.168.1.16"), 28);
			AddSubnet(IPAddress.Parse("fec0::"), 10);
			_thread.Start();
		}

		public void Stop() {
		}

		public void AddSubnet(IPAddress addr, int prefix) {
			if (addr.AddressFamily == AddressFamily.InterNetwork) {
				if (prefix < 0 || prefix > 32) {
					throw new Exception("Subnet prefix length " + prefix + " invalid for family " + addr.AddressFamily);
				}
			} else if (addr.AddressFamily == AddressFamily.InterNetworkV6) {
				if (prefix < 0 || prefix > 128) {
					throw new Exception("Subnet prefix length " + prefix + " invalid for family " + addr.AddressFamily);
				}
			} else {
				throw new Exception("Unknown address family " + addr.AddressFamily);
			}

			_subnets.Add(addr, prefix);
		}

		private void threadLoop() {
			byte[] data = new byte[2048];

			while (true) {
				if (!_socket.WaitForReadable())
					continue;

				int datalen = _socket.Receive(data);
				if (datalen < 14)
					continue;

				int etherType = (data[12] << 8) | data[13];
				if (etherType == 0x0806) {
					if (datalen < 22) {
						/* XXX: Should too small ARP packet be reported? */
						continue;
					}

					/* XXX: Handle ARP packet */
					int opcode = (data[20] << 8) | data[21];
					if (opcode == 1) {
						handleARPRequest(data, datalen);
					} else if (opcode == 2) {
						handleARPReply(data, datalen);
					} else if (opcode == 3 || opcode == 4) {
						/* This is a RARP request not handled */
					} else {
						throw new Exception("Invalid ARP opcode: " + opcode);
					}
				} else if (etherType == 0x0800) {
					/* XXX: Handle IPv4 packet */
				} else if (etherType == 0x86dd) {
					/* XXX: Handle IPv6 packet */
					
					if (data[14+6] == 58 && data[14+7] == 255) {
						/* ICMPv6 packet found */
						int type = data[14+40];

						if (type == 135) {
							handleNDSol(data, datalen);
						} else if (type == 136) {
							handleNDAdv(data, datalen);
						}
					}
				}
			}
		}

		private bool addressInSubnet(IPAddress addr) {
			foreach (IPAddress netaddr in _subnets.Keys) {
				if (addr.AddressFamily != netaddr.AddressFamily)
					continue;

				byte[] b1 = addr.GetAddressBytes();
				byte[] b2 = netaddr.GetAddressBytes();
				int prefix = _subnets[netaddr];

				bool found = true;
				for (int i=0; i <= (prefix-1)/8; i++) {
					if (i < prefix/8) {
						/* Full bytes compared */
						if (b1[i] != b2[i]) {
							found = false;
							break;
						}
					} else {
						/* number of discarded bits */
						int disc = 8 - (prefix % 8);
						if ((b1[i] >> disc) != (b2[i] >> disc)) {
							found = false;
							break;
						}
					}
				}

				if (found) {
					return true;
				}
			}

			return false;
		}

		private void handleARPRequest(byte[] data, int datalen) {
			if (data[14] != 0x00 || data[15] != 0x01 || // Hardware type: Ethernet
			    data[16] != 0x08 || data[17] != 0x00 || // Protocol type: IP
			    data[18] != 0x06 || data[19] != 0x04 || // Hw size: 6, Proto size: 4
			    data[20] != 0x00 || data[21] != 0x01) { // Opcode: request
				/* XXX: Should invalid ARP request be reported? */
				return;
			}

			byte[] ipaddr = new byte[4];
			Array.Copy(data, 38, ipaddr, 0, 4);
			IPAddress addr = new IPAddress(ipaddr);

			if (!addressInSubnet(addr)) {
				return;
			}

			Array.Copy(data, 6, data, 0, 6);
			Array.Copy(_hwaddr, 0, data, 6, 6);

			Array.Copy(data, 22, data, 32, 10);
			Array.Copy(_hwaddr, 0, data, 22, 6);
			Array.Copy(ipaddr, 0, data, 28, 4);

			/* Change opcode type into reply */
			data[21] = 0x02;

			_socket.Send(data, datalen);
			Console.WriteLine("Replied to ARP packet with IP {0}", addr);
		}

		private void handleARPReply(byte[] data, int datalen) {
			if (data[14] != 0x00 || data[15] != 0x01 || // Hardware type: Ethernet
			    data[16] != 0x08 || data[17] != 0x00 || // Protocol type: IP
			    data[18] != 0x06 || data[19] != 0x04 || // Hw size: 6, Proto size: 4
			    data[20] != 0x00 || data[21] != 0x02) { // Opcode: reply
				/* XXX: Should invalid ARP reply be reported? */
				return;
			}

			byte[] hwaddr = new byte[6];
			Array.Copy(data, 22, hwaddr, 0, 6);

			byte[] ipaddr = new byte[4];
			Array.Copy(data, 28, ipaddr, 0, 4);
			IPAddress addr = new IPAddress(ipaddr);

			/* We don't want local addresses into ARP table */
			for (int i=0; i<6; i++) {
				if (hwaddr[i] != _hwaddr[i]) {
					break;
				} else if (i == 5) {
					Console.WriteLine("Local hardware address {0} not added to ARP table",
						BitConverter.ToString(hwaddr).Replace('-', ':').ToLower());
					return;
				}
			}

			if (_arptable.ContainsKey(addr)) {
				Console.WriteLine("Hardware address for IP {0} already known", addr);
				return;
			}

			_arptable.Add(addr, hwaddr);
			Console.WriteLine("Added hardware address {0} for IP address {1} into ARP table",
				BitConverter.ToString(hwaddr).Replace('-', ':').ToLower(), addr);
		}

		private void handleNDSol(byte[] data, int datalen) {
		}

		private void handleNDAdv(byte[] data, int datalen) {
			/* FIXME: Validate the packet header fields */
			if (data[20] != 58 || data[21] != 255 || // ICMPv6, hop=255
			    data[18] !=  0 || data[19] != 32  || // Length: 24 bytes + 8 byte option
			    data[78] !=  2 || data[79] !=  1) {  // Option: target lladdr
				/* XXX: Should invalid ARP reply be reported? */
				return;
			}

			byte[] ipaddr = new byte[4];
			Array.Copy(data, 62, ipaddr, 0, 4);
			IPAddress addr = new IPAddress(ipaddr);

			byte[] hwaddr = new byte[6];
			Array.Copy(data, 80, hwaddr, 0, 6);

			/* Check if source IP address is zero */
			for (int i=0; i<16; i++) {
				if (data[14+8+i] != 0) {
					break;
				} else if (i == 15) {
					/* No non-zero bytes found, it is a DAD packet */
					return;
				}
			}

			/* We don't want local addresses into ARP table */
			for (int i=0; i<6; i++) {
				if (hwaddr[i] != _hwaddr[i]) {
					break;
				} else if (i == 5) {
					Console.WriteLine("Local hardware address {0} not added to ARP table",
						BitConverter.ToString(hwaddr).Replace('-', ':').ToLower());
					return;
				}
			}

			if (_arptable.ContainsKey(addr)) {
				Console.WriteLine("Hardware address for IP {0} already known", addr);
				return;
			}

			_arptable.Add(addr, hwaddr);
			Console.WriteLine("Added hardware address {0} for IP address {1} into ARP table",
				BitConverter.ToString(hwaddr).Replace('-', ':').ToLower(), addr);
		}
	}
}
