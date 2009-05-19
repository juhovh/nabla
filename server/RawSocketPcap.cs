/**
 *  NABLA - Automatic IP Tunneling and Connectivity
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
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;


namespace Nabla.RawSocket {
	public class RawSocketPcap : RawSocket {
		private const int PCAP_ERRBUF_SIZE = 256;
		private const int DLT_EN10MB = 1;
		private const int MAX_PACKET_SIZE = 4096;

		private bool _disposed = false;
		IntPtr _header = IntPtr.Zero;
		IntPtr _data = IntPtr.Zero;
		byte[] _readbuf = new byte[512];

		IntPtr _handle;
		int _protocol;
		AddressFamily _family;

		[StructLayout(LayoutKind.Sequential)]
		private struct timeval {
			public IntPtr tv_sec;
			public IntPtr tv_usec;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct pcap_pkthdr {
			public timeval  ts;
			public UInt32   caplen;
			public UInt32   len;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct pcap_if {
			public IntPtr next;
			public string name;
			public string description;
			public IntPtr addresses;
			public UInt32 flags;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct pcap_addr {
			public IntPtr next;
			public IntPtr addr;
			public IntPtr netmask;
			public IntPtr broadaddr;
			public IntPtr dstaddr;
		}

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static IntPtr pcap_open_live(string dev, int packetLen, short mode, short timeout, StringBuilder errbuf);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static int pcap_datalink(IntPtr handle);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static void pcap_close(IntPtr handle);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static IntPtr pcap_geterr(IntPtr handle);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static int pcap_inject(IntPtr handle, byte[] data, int size);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static int pcap_next_ex(IntPtr handle, ref IntPtr header, ref IntPtr data);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		private extern static int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);

		[DllImport("wpcap.dll", CharSet=CharSet.Ansi)]
		internal extern static void pcap_freealldevs(IntPtr alldevs);


		private void getAddresses(string ifname) {
			List<IPAddress> addresses = new List<IPAddress>();

			IntPtr ifaces = IntPtr.Zero;
			StringBuilder errbuf = new StringBuilder(PCAP_ERRBUF_SIZE); 

			int ret = pcap_findalldevs(ref ifaces, errbuf);
			if (ret == -1) {
				throw new Exception("Error in pcap_findalldevs(): " + errbuf);
			}

			IntPtr curr = ifaces;
			while (curr != IntPtr.Zero) {
				pcap_if iface = (pcap_if) Marshal.PtrToStructure(curr, typeof(pcap_if));
				curr = iface.next;

				string id;
				if (Environment.OSVersion.Platform == PlatformID.Unix) {
					id = iface.name;	
				} else {
					id = iface.description;
				}

				if (!ifname.Equals(id)) {
					continue;
				}

				if (iface.addresses != IntPtr.Zero) {
					IntPtr curr_addr = iface.addresses;
					while (curr_addr != IntPtr.Zero) {
						pcap_addr addr = (pcap_addr) Marshal.PtrToStructure(curr_addr, typeof(pcap_addr));
						curr_addr = addr.next;

						byte byte1 = Marshal.ReadByte(addr.addr, 0);
						byte byte2 = Marshal.ReadByte(addr.addr, 1);

						AddressFamily family;
						if ((byte1 == 17 && byte2 == 0) || (byte1 == 0 && byte2 == 17)) {
							/* This should be AF_INET on platform without sa_len */
							family = AddressFamily.InterNetwork;
						} else if (byte1 == 16 && byte2 == 2) {
							/* This should be AF_INET on platform with sa_len */
							family = AddressFamily.InterNetwork;
						} else if (byte1 == 23 && byte2 == 0) {
							/* This should be AF_INET6 on Windows */
							family = AddressFamily.InterNetworkV6;
						} else if ((byte1 == 10 && byte2 == 0) || (byte1 == 0 && byte2 == 10)) {
							/* This should be AF_INET6 on Linux */
							family = AddressFamily.InterNetworkV6;
						} else if (byte1 == 28 && byte2 == 30) {
							/* This should be AF_INET6 on BSD with sa_len */
							family = AddressFamily.InterNetworkV6;
						} else if ((byte1 == 26 && byte2 == 0) || (byte1 == 0 && byte2 == 26)) {
							/* This should be AF_INET6 on Solaris */
							family = AddressFamily.InterNetworkV6;
						} else  {
							family = AddressFamily.Unknown;
						}

						if (family == AddressFamily.InterNetwork) {
							SocketAddress socketAddress = new SocketAddress(family, 16);
							for (int i=2; i<socketAddress.Size; i++)
								socketAddress[i] = Marshal.ReadByte(addr.addr, i);
							IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, 0);
							endPoint = (IPEndPoint) endPoint.Create(socketAddress);
							addresses.Add(endPoint.Address);
						} else if (family == AddressFamily.InterNetworkV6) {
							SocketAddress socketAddress = new SocketAddress(family, 28);
							for (int i=2; i<socketAddress.Size; i++)
								socketAddress[i] = Marshal.ReadByte(addr.addr, i);
							IPEndPoint endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
							endPoint = (IPEndPoint) endPoint.Create(socketAddress);
							addresses.Add(endPoint.Address);
						}
					}
				}
			}
			pcap_freealldevs(ifaces);

			foreach (IPAddress addr in addresses) {
				Console.WriteLine("Found IP address: " + addr);
			}
		}

		private string findInterface(string ifname) {
			string interfaceId = null;

			IntPtr ifaces = IntPtr.Zero;
			StringBuilder errbuf = new StringBuilder(PCAP_ERRBUF_SIZE); 

			int ret = pcap_findalldevs(ref ifaces, errbuf);
			if (ret == -1) {
				throw new Exception("Error in pcap_findalldevs(): " + errbuf);
			}

			IntPtr curr = ifaces;
			while (curr != IntPtr.Zero) {
				pcap_if iface = (pcap_if) Marshal.PtrToStructure(curr, typeof(pcap_if));
				curr = iface.next;

				string id;
				if (Environment.OSVersion.Platform == PlatformID.Unix) {
					id = iface.name;	
				} else {
					id = iface.description;
				}

				if (ifname.Equals(id)) {
					interfaceId = iface.name;
					break;
				}
			}
			pcap_freealldevs(ifaces);
			if (interfaceId == null) {
				throw new Exception("Cannot find adapter '" + ifname);
			}

			return interfaceId;
		}

		public static new byte[] GetHardwareAddress(string ifname) {
			byte[] hwaddr = null;

			IntPtr ifaces = IntPtr.Zero;
			StringBuilder errbuf = new StringBuilder(PCAP_ERRBUF_SIZE); 

			int ret = pcap_findalldevs(ref ifaces, errbuf);
			if (ret == -1) {
				throw new Exception("Error in pcap_findalldevs(): " + errbuf);
			}

			IntPtr curr = ifaces;
			while (curr != IntPtr.Zero) {
				pcap_if iface = (pcap_if) Marshal.PtrToStructure(curr, typeof(pcap_if));
				curr = iface.next;

				string id;
				if (Environment.OSVersion.Platform == PlatformID.Unix) {
					id = iface.name;	
				} else {
					id = iface.description;
				}

				if (!ifname.Equals(id)) {
					continue;
				}

				if (iface.addresses != IntPtr.Zero) {
					IntPtr curr_addr = iface.addresses;
					while (curr_addr != IntPtr.Zero) {
						pcap_addr addr = (pcap_addr) Marshal.PtrToStructure(curr_addr, typeof(pcap_addr));
						curr_addr = addr.next;

						byte byte1 = Marshal.ReadByte(addr.addr, 0);
						byte byte2 = Marshal.ReadByte(addr.addr, 1);

						if ((byte1 == 17 && byte2 == 0) || (byte1 == 0 && byte2 == 17)) {
							/* This should be Linux sockaddr_ll, address at 12 */
							hwaddr = new byte[6];
							for (int i=0; i<6; i++)
								hwaddr[i] = Marshal.ReadByte(addr.addr, 12+i);
						} else if (byte1 == 20 && byte2 == 18) {
							/* This should be BSD sockaddr_dl, address at 8+(namelen) */
							hwaddr = new byte[6];
							int ifnlen = Marshal.ReadByte(addr.addr, 5);
							for (int i=0; i<6; i++)
								hwaddr[i] = Marshal.ReadByte(addr.addr, 8+ifnlen+i);
						} else {
							continue;
						}
						break;
					}
				}
			}
			pcap_freealldevs(ifaces);
			if (hwaddr == null) {
				throw new Exception("Error getting hardware address for interface " + ifname);
			}

			return hwaddr;
		}

		public RawSocketPcap(string ifname, AddressFamily addressFamily, int protocol, int waitms) {
			int ret;

			if (ifname == null) {
				throw new Exception("Interface name required for pcap capture");
			}

			if (addressFamily != AddressFamily.DataLink &&
			    addressFamily != AddressFamily.InterNetwork &&
			    addressFamily != AddressFamily.InterNetworkV6) {
				throw new Exception("Address family '" + addressFamily + "' not supported");
			}

			getAddresses(ifname);

			/* Map the human readable name to the name to open */
			string interfaceId = findInterface(ifname);
			StringBuilder errbuf = new StringBuilder(PCAP_ERRBUF_SIZE);
			_handle = pcap_open_live(interfaceId, MAX_PACKET_SIZE, 0, (short) waitms, errbuf);
			if (_handle == IntPtr.Zero) {
				throw new Exception("Unable to open adapter '" + ifname + "': " + errbuf);
			}

			ret = pcap_datalink(_handle);
			if (ret != DLT_EN10MB) {
				throw new Exception("Unsupported datalink type (" + ret + "), should be DLT_EN10MB");
			}

			_protocol = protocol;
			_family = addressFamily;
		}

		public override void Bind(EndPoint localEP) {
		}

		public override bool WaitForWritable() {
			return true;
		}

		public override int SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP) {
			int ret;

			byte[] outbuf;
			if (_family == AddressFamily.InterNetwork) {
				/* Ethernet + IPv4 header size */
				outbuf = new byte[14 + 20 + size];

				/* XXX: Construct Ethernet and IPv4 headers */

				Array.Copy(buffer, offset, outbuf, 14+20, size);
			} else if (_family == AddressFamily.InterNetworkV6) {
				/* Ethernet + IPv6 header size */
				outbuf = new byte[14 + 40 + size];

				/* XXX: Construct Ethernet and IPv6 headers */

				Array.Copy(buffer, offset, outbuf, 14+40, size);
			} else {
				outbuf = new byte[size];
				Array.Copy(buffer, offset, outbuf, 0, size);
			}

			ret = (outbuf[12] << 8) | outbuf[13];
			if (ret != _protocol) {
				throw new Exception("Ethernet frame type (" + ret + ") incorrect");
			}

			ret = pcap_inject(_handle, outbuf, size);

			return ret;
		}

		public override bool WaitForReadable() {
			int requiredType = 0;
			int ret;

			if (_header != IntPtr.Zero && _data != IntPtr.Zero) {
				return true;
			}

			if (_family == AddressFamily.InterNetwork) {
				requiredType = 0x0800;
			} else if (_family == AddressFamily.InterNetworkV6) {
				requiredType = 0x86dd;
			}

			while (true) {
				_header = IntPtr.Zero;
				_data = IntPtr.Zero;
				ret = pcap_next_ex(_handle, ref _header, ref _data);

				if (ret < 0) {
					/* XXX: Fix the pcap_geterr */
					throw new Exception("Error reading packet: " + pcap_geterr(_handle));
				} else if (ret == 0) {
					/* Read timed out */
					return false;
				} else if (requiredType > 0) {
					/* Check that received type match the required one */
					int type = Marshal.ReadByte(_data, 12) << 8 |
					           Marshal.ReadByte(_data, 13);

					if (type != requiredType) {
						/* XXX: Should return 0 here if timeout elapsed */

						continue;
					}

					break;
				} else {
					/* Any type is accepted and data was read, return */
					break;
				}
			}

			return true;
		}

		public override int ReceiveFrom(byte[] buffer, int offset, int size, ref EndPoint remoteEP) {
			bool readable;
			int packetOffset;
			int ret;

			while (true) {
				readable = false;
				while (!readable) {
					readable = WaitForReadable();
				}

				if (_header == IntPtr.Zero || _data == IntPtr.Zero) {
					throw new Exception("Header or data null after pcap read");
				}

				pcap_pkthdr pkt_header = (pcap_pkthdr) Marshal.PtrToStructure(_header, typeof(pcap_pkthdr));
				if (pkt_header.caplen != pkt_header.len) {
					throw new Exception("Incoming packet didn't fit into internal buffer");
				}
				if (pkt_header.caplen > _readbuf.Length)
					_readbuf = new byte[pkt_header.caplen];
				Marshal.Copy(_data, _readbuf, 0, (int) pkt_header.caplen);
				_header = IntPtr.Zero;
				_data = IntPtr.Zero;

				if (_family == AddressFamily.InterNetwork) {
					packetOffset = 14;
					packetOffset += (_readbuf[14] & 0x0f) * 4;

					/* XXX: Should check for the destination address and protocol type */
				} else if (_family == AddressFamily.InterNetworkV6) {
					packetOffset = 40;

					/* XXX: Should check for the destination address and protocol type */
				} else {
					packetOffset = 0;

					int protocol = (_readbuf[12] << 8) | _readbuf[13];
					if (protocol != _protocol) {
						continue;
					}
				}

				if (pkt_header.caplen - packetOffset > size) {
					throw new Exception("Incoming packet didn't fit into given external buffer");
				}

				Array.Copy(_readbuf, packetOffset, buffer, offset, pkt_header.caplen - packetOffset);
				ret = (int) pkt_header.caplen - packetOffset;
				break;
			}

			return ret;
		}

		public void Dispose() {
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// Managed resources can be disposed here
				}

				pcap_close(_handle);
				_disposed = true;
			}
		}
	}
}

