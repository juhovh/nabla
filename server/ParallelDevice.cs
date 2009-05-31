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

		public ParallelDevice(string deviceName) {
			_hwaddr = RawSocket.GetHardwareAddress(deviceName);
			_socket = RawSocket.GetRawSocket(deviceName,
			                                 AddressFamily.DataLink,
			                                 0, 100);
			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start() {
			_subnets.Add(IPAddress.Parse("192.168.1.16"), 28);
			_thread.Start();
		}

		public void Stop() {
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
					/* XXX: Handle ARP packet */
					Console.WriteLine("Got ARP packet");
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
					Console.WriteLine("Got IPv4 packet");
				} else if (etherType == 0x86dd) {
					/* XXX: Handle IPv6 packet */
					Console.WriteLine("Got IPv6 packet");
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
					Console.WriteLine("Comparing bytes {0} {1}", b1[i], b2[i]);
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
			if (!addressInSubnet(new IPAddress(ipaddr))) {
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
		}

		private void handleARPReply(byte[] data, int datalen) {
		}
	}
}
