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
	public class IPConfig {
		public readonly IPAddress Address;
		public readonly int PrefixLength;
		public readonly IPAddress DefaultRoute;

		public IPConfig(IPAddress addr, int prefixlen, IPAddress route) {
			if (addr.AddressFamily == AddressFamily.InterNetwork) {
				if (prefixlen < 0 || prefixlen > 32) {
					throw new Exception("Subnet prefix length " + prefixlen + " invalid for family " + addr.AddressFamily);
				}
			} else if (addr.AddressFamily == AddressFamily.InterNetworkV6) {
				if (prefixlen < 0 || prefixlen > 128) {
					throw new Exception("Subnet prefix length " + prefixlen + " invalid for family " + addr.AddressFamily);
				}
			} else {
				throw new Exception("Unknown address family " + addr.AddressFamily);
			}

			Address = addr;
			PrefixLength = prefixlen;
			DefaultRoute = route;
		}
	}

	public delegate void ReceivePacketCallback(byte[] data);

	public class ParallelDevice {
		byte[] _hwaddr;
		RawSocket _socket;
		Thread _thread;

		Dictionary<IPAddress, IPConfig> _subnets
			= new Dictionary<IPAddress, IPConfig>();

		Object _arplock = new Object();
		Dictionary<IPAddress, byte[]> _arptable
			= new Dictionary<IPAddress, byte[]>();

		public ReceivePacketCallback ReceivePacketCallback = null;

		public ParallelDevice(string deviceName) {
			_hwaddr = RawSocket.GetHardwareAddress(deviceName);
			_socket = RawSocket.GetRawSocket(deviceName,
			                                 AddressFamily.DataLink,
			                                 0, 100);
			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start() {
			_thread.Start();
		}

		public void Stop() {
		}

		public void AddSubnet(IPAddress addr, int prefixlen, IPAddress route) {
			_subnets.Add(addr, new IPConfig(addr, prefixlen, route));
		}

		public void SendPacket(byte[] data) {
			SendPacket(data, data.Length);
		}

		public void SendPacket(byte[] data, int datalen) {
			SendPacket(data, 0, datalen);
		}

		public void SendPacket(byte[] data, int offset, int datalen) {
			int version = (data[offset] >> 4) & 0x0f;

			IPAddress src;
			IPAddress dest;
			bool multicast;
			if (version == 4) {
				byte[] ipaddr = new byte[4];

				Array.Copy(data, offset+12, ipaddr, 0, 4);
				src = new IPAddress(ipaddr);

				Array.Copy(data, offset+16, ipaddr, 0, 4);
				dest = new IPAddress(ipaddr);
				multicast = (ipaddr[0] < 224 && ipaddr[0] > 239);
			} else if (version == 6) {
				byte[] ipaddr = new byte[16];

				Array.Copy(data, offset+8, ipaddr, 0, 16);
				src = new IPAddress(ipaddr);

				Array.Copy(data, offset+24, ipaddr, 0, 16);
				dest = new IPAddress(ipaddr);
				multicast = dest.IsIPv6Multicast;
			} else {
				throw new Exception("Invalid IP packet version: " + version);
			}

			if (!addressInSubnet(src)) {
				throw new Exception("Source address " + src + " not in range");
			}

			byte[] hwaddr;
			if (multicast) {
				if (dest.AddressFamily == AddressFamily.InterNetwork) {
					hwaddr = new byte[6];
					hwaddr[0] = 0x01;
					hwaddr[1] = 0x00;
					hwaddr[2] = 0x5e;
					Array.Copy(dest.GetAddressBytes(), 1, hwaddr, 3, 3);

					/* The highest bit of address part should be 0 */
					hwaddr[3] = (byte) (hwaddr[3] & 0x7f);
				} else {
					/* IPv6 multicast address from last 32 bits */
					hwaddr = new byte[6];
					hwaddr[0] = 0x33;
					hwaddr[1] = 0x33;
					Array.Copy(dest.GetAddressBytes(), 12, hwaddr, 2, 4);
				}
			} else {
				if (!addressInSubnet(dest)) {
					IPAddress route = null;

					foreach (IPConfig conf in _subnets.Values) {
						if (conf.Address.AddressFamily == dest.AddressFamily &&
						    conf.DefaultRoute != null) {
							route = conf.DefaultRoute;
						}
					}
					if (route == null) {
						throw new Exception("Address " + dest + " not a local address and default route not found");
					}

					dest = route;
				}

				lock (_arplock) {
					/* Wait one second between requests */
					TimeSpan span = new TimeSpan(0, 0, 1);

					for (int i=0; i<3; i++) {
						DateTime startTime = DateTime.Now;

						while (!_arptable.ContainsKey(dest)) {
							if (dest.AddressFamily == AddressFamily.InterNetwork) {
								sendARPRequest(src, dest);
							} else {
								sendNDSol(src, dest);
							}

							TimeSpan wait = (startTime + span) - DateTime.Now;
							if (wait < TimeSpan.Zero)
								break;

							Monitor.Wait(_arplock, wait);
						}

						if (_arptable.ContainsKey(dest))
							break;
					}

					if (!_arptable.ContainsKey(dest)) {
						throw new Exception("Couldn't find hardware address for " + dest);
					}

					hwaddr = _arptable[dest];
				}
			}

			byte[] outbuf = new byte[14+datalen];
			Array.Copy(hwaddr, 0, outbuf, 0, 6);
			Array.Copy(_hwaddr, 0, outbuf, 6, 6);
			if (dest.AddressFamily == AddressFamily.InterNetwork) {
				outbuf[12] = 0x08;
				outbuf[13] = 0x00;
			} else {
				outbuf[12] = 0x86;
				outbuf[13] = 0xdd;
			}
			Array.Copy(data, offset, outbuf, 14, datalen);

			_socket.Send(outbuf);
			Console.WriteLine("Sent packet to host " + dest);
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
					if (datalen < 14+20) {
						/* XXX: Should too small IPv4 packet be reported? */
						continue;
					}

					/* Get destination address */
					byte[] ipaddr = new byte[4];
					Array.Copy(data, 26, ipaddr, 0, 4);
					IPAddress addr = new IPAddress(ipaddr);

					if ((ipaddr[0] < 224 && ipaddr[0] > 239) && !addressInSubnet(addr)) {
						/* Packet not destined to us */
						continue;
					}
				} else if (etherType == 0x86dd) {
					if (datalen < 14+40) {
						/* XXX: Should too small IPv6 packet be reported? */
						continue;
					}
					
					if (data[14+6] == 58 && data[14+7] == 255) {
						if (datalen < 14+40+8) {
							/* XXX: Should too small ICMPv6 packet be reported? */
							continue;
						}

						/* ICMPv6 packet found */
						int type = data[14+40];

						if (type == 135) {
							handleNDSol(data, datalen);
							continue;
						} else if (type == 136) {
							handleNDAdv(data, datalen);
							continue;
						}
					}

					/* Get destination address */
					byte[] ipaddr = new byte[16];
					Array.Copy(data, 38, ipaddr, 0, 16);
					IPAddress addr = new IPAddress(ipaddr);

					if (!addr.IsIPv6Multicast && !addressInSubnet(addr)) {
						/* Packet not destined to us */
						continue;
					}
				}

				if (ReceivePacketCallback != null) {
					byte[] outbuf = new byte[data.Length - 14];
					Array.Copy(data, 14, outbuf, 0, outbuf.Length);
					ReceivePacketCallback(outbuf);
				}
			}
		}

		private bool addressInSubnet(IPAddress addr) {
			foreach (IPAddress netaddr in _subnets.Keys) {
				if (addr.AddressFamily != netaddr.AddressFamily)
					continue;

				byte[] b1 = addr.GetAddressBytes();
				byte[] b2 = netaddr.GetAddressBytes();
				int prefixlen = _subnets[netaddr].PrefixLength;

				bool found = true;
				for (int i=0; i <= (prefixlen-1)/8; i++) {
					if (i < prefixlen/8) {
						/* Full bytes compared */
						if (b1[i] != b2[i]) {
							found = false;
							break;
						}
					} else {
						/* number of discarded bits */
						int disc = 8 - (prefixlen % 8);
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

		private void sendARPRequest(IPAddress source, IPAddress dest) {
			if (source.AddressFamily != AddressFamily.InterNetwork ||
			    dest.AddressFamily != AddressFamily.InterNetwork) {
				throw new Exception("Address of wrong type");
			}

			byte[] data = new byte[42];

			/* Construct Ethernet header for broadcast address */
			for (int i=0; i<6; i++)
				data[i] = 0xff;
			Array.Copy(_hwaddr, 0, data, 6, 6);
			data[12] = 0x08;
			data[13] = 0x06;

			/* Construct ARP packet */
			data[14] = 0x00;
			data[15] = 0x01; // Hardware type: Ethernet
			data[16] = 0x08;
			data[17] = 0x00; // Protocol type: IP
			data[18] = 6;    // Hardware size: 6
			data[19] = 4;    // Protocol size: 4
			data[20] = 0x00;
			data[21] = 0x01; // Opcode: request
			Array.Copy(_hwaddr, 0, data, 22, 6);
			Array.Copy(source.GetAddressBytes(), 0, data, 28, 4);
			Array.Copy(dest.GetAddressBytes(), 0, data, 38, 4);

			_socket.Send(data);
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

			lock (_arplock) {
				if (_arptable.ContainsKey(addr)) {
					Console.WriteLine("Hardware address for IP {0} already known", addr);
					return;
				}
				_arptable.Add(addr, hwaddr);
				Monitor.PulseAll(_arplock);
			}

			Console.WriteLine("Added hardware address {0} for IP address {1} into ARP table",
				BitConverter.ToString(hwaddr).Replace('-', ':').ToLower(), addr);
		}

		private void sendNDSol(IPAddress source, IPAddress dest) {
			if (source.AddressFamily != AddressFamily.InterNetworkV6 ||
			    dest.AddressFamily != AddressFamily.InterNetworkV6) {
				throw new Exception("Address of wrong type");
			}

			byte[] ipaddr = dest.GetAddressBytes();

			/* Construct Ethernet header for Solicited-Node Address */
			byte[] data = new byte[86];
			data[0] = 0x33;
			data[1] = 0x33;
			data[2] = 0xff;
			Array.Copy(ipaddr, 13, data, 3, 3);
			Array.Copy(_hwaddr, 0, data, 6, 6);
			data[12] = 0x86;
			data[13] = 0xdd;

			/* Construct IPv6 header for Solicited-Node Address */
			int length = 8+16+8;
			data[14] = 0x60;                  // IP version 6
			data[18] = (byte) (length >> 8);
			data[19] = (byte)  length;
			data[20] = 58;                    // next header ICMPv6
			data[21] = 255;                   // hop limit 255
			Array.Copy(source.GetAddressBytes(), 0, data, 22, 16);
			data[38] = 0xff;
			data[39] = 0x02;
			data[48] = 0x01;
			data[49] = 0xff;
			Array.Copy(ipaddr, 13, data, 50, 3);

			/* Construct ICMPv6 packet with source link-layer address option */
			data[54] = 135;
			Array.Copy(ipaddr, 0, data, 62, 16);
			data[78] = 1;
			data[79] = 1;
			Array.Copy(_hwaddr, 0, data, 80, 6);

			/* Add pseudo-header into the checksum */
			int checksum = 0;
			checksum += data[14+4] << 8 | data[14+5];
			checksum += data[14+6];
			for (int i=0; i<32; i++)
				checksum += data[14+8+i] << ((i%2 == 0)?8:0);

			/* Checksum the actual data */
			for (int i=0; i<length; i++)
				checksum += data[14+40+i] << ((i%2 == 0)?8:0);

			/* Store the final checksum into ICMPv6 packet */
			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;
			data[14+40+2] = (byte) (checksum >> 8);
			data[14+40+3] = (byte)  checksum;

			_socket.Send(data);
		}

		private void handleNDSol(byte[] data, int datalen) {
			/* XXX: The 8 byte source lladdr option is not necessary */
			if (data[18] !=   0 || data[19] !=  32 || // Length: 24 bytes + 8 byte option
			    data[20] !=  58 || data[21] != 255 || // ICMPv6, hop=255
			    data[54] != 135 || data[55] !=   0 || // Type: 135, Code: 0
			    data[78] !=   1 || data[79] !=   1) { // Option: source lladdr
				/* XXX: Should invalid NDSol be reported? */
				return;
			}

			byte[] ipaddr = new byte[16];
			Array.Copy(data, 62, ipaddr, 0, 16);
			IPAddress addr = new IPAddress(ipaddr);

			if (!addressInSubnet(addr)) {
				return;
			}

			/* Neighbor advert is ICMPv6 header, IPv6 address and
			 * 8 bytes of target link-layer address option */
			int length = 8+16+8;

			/* Set Ethernet src/dst */
			Array.Copy(data, 6, data, 0, 6);
			Array.Copy(_hwaddr, 0, data, 6, 6);

			/* Add packet content length */
			data[14+4] = (byte) (length >> 8);
			data[14+5] = (byte)  length;

			/* Set IPv6 src/dst */
			Array.Copy(data, 22, data, 38, 16); /* Destination address (from source) */
			Array.Copy(data, 62, data, 22, 16); /* Source address (from ICMPv6 packet) */

			/* Set ICMPv6 type and code */
			data[14+40] = 136;
			data[14+41] = 0;

			/* Add target link-layer address option */
			data[14+40+8+16] = 2;
			data[14+40+8+17] = 1;
			Array.Copy(_hwaddr, 0, data, 80, 6);

			/* Zero checksum */
			int checksum = 0;
			data[14+40+2] = 0;
			data[14+40+3] = 0;

			/* Add pseudo-header into the checksum */
			checksum += data[14+4] << 8 | data[14+5];
			checksum += data[14+6];
			for (int i=0; i<32; i++)
				checksum += data[14+8+i] << ((i%2 == 0)?8:0);

			/* Checksum the actual data */
			for (int i=0; i<length; i++)
				checksum += data[14+40+i] << ((i%2 == 0)?8:0);

			/* Store the final checksum into ICMPv6 packet */
			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;
			data[14+40+2] = (byte) (checksum >> 8);
			data[14+40+3] = (byte)  checksum;

			_socket.Send(data, 14+40+length);
			Console.WriteLine("Replied to Neighbor Solicitation with IP {0}", addr);
		}

		private void handleNDAdv(byte[] data, int datalen) {
			if (data[18] !=   0 || data[19] !=  32 || // Length: 24 bytes + 8 byte option
			    data[20] !=  58 || data[21] != 255 || // ICMPv6, hop=255
			    data[54] != 136 || data[55] !=   0 || // Type: 135, Code: 0
			    data[78] !=   2 || data[79] !=   1) { // Option: target lladdr
				/* XXX: Should invalid NDAdv be reported? */
				return;
			}

			byte[] ipaddr = new byte[16];
			Array.Copy(data, 62, ipaddr, 0, 16);
			IPAddress addr = new IPAddress(ipaddr);

			byte[] hwaddr = new byte[6];
			Array.Copy(data, 80, hwaddr, 0, 6);

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

			lock (_arplock) {
				if (_arptable.ContainsKey(addr)) {
					Console.WriteLine("Hardware address for IP {0} already known", addr);
					return;
				}

				_arptable.Add(addr, hwaddr);
				Monitor.PulseAll(_arplock);
			}

			Console.WriteLine("Added hardware address {0} for IP address {1} into ARP table",
				BitConverter.ToString(hwaddr).Replace('-', ':').ToLower(), addr);
		}
	}
}