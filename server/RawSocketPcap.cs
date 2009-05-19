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


namespace Nabla.RawSocket {
	public class RawSocketPcap : RawSocket {
		private const int PCAP_ERRBUF_SIZE = 256;
		private const int DLT_EN10MB = 1;
		private const int MAX_PACKET_SIZE = 4096;

		private bool _disposed = false;
		IntPtr _header = IntPtr.Zero;
		IntPtr _data = IntPtr.Zero;

		IntPtr _handle;
		int _protocol;

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

				if (iface.name.Equals(ifname) && iface.addresses != IntPtr.Zero) {
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
				curr = iface.next;
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

			if (addressFamily != AddressFamily.DataLink) {
				throw new Exception("Address family '" + addressFamily + "' not supported");
			}

			StringBuilder errbuf = new StringBuilder(PCAP_ERRBUF_SIZE);
			_handle = pcap_open_live(ifname, MAX_PACKET_SIZE, 0, (short) waitms, errbuf);
			if (_handle == IntPtr.Zero) {
				throw new Exception("Unable to open adapter '" + ifname + "': " + errbuf);
			}

			ret = pcap_datalink(_handle);
			if (ret != DLT_EN10MB) {
				throw new Exception("Unsupported datalink type (" + ret + "), should be DLT_EN10MB");
			}

			_protocol = protocol;
		}

		public override void Bind(EndPoint localEP) {
		}

		public override bool WaitForWritable() {
			return true;
		}

		public override int SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP) {
			int ret;

			/* This is really ugly but has to do for now */
			if (offset != 0) {
				byte[] newbuf = new byte[size];
				Array.Copy(buffer, offset, newbuf, 0, size);
				buffer = newbuf;
			}

			ret = (buffer[12] << 8) | buffer[13];
			if (ret != _protocol) {
				throw new Exception("Ethernet frame type (" + ret + ") incorrect");
			}

			ret = pcap_inject(_handle, buffer, size);

			return ret;
		}

		public override bool WaitForReadable() {
			int ret;

			if (_header != IntPtr.Zero && _data != IntPtr.Zero) {
				return true;
			}

			ret = pcap_next_ex(_handle, ref _header, ref _data);
			if (ret < 0) {
				/* XXX: Fix the pcap_geterr */
				throw new Exception("Error reading packet: " + pcap_geterr(_handle));
			}

			return ((ret > 0) ? true : false);
		}

		public override int ReceiveFrom(byte[] buffer, int offset, int size, ref EndPoint remoteEP) {
			bool readable = false;

			while (!readable) {
				readable = WaitForReadable();
			}

			if (_header == IntPtr.Zero || _data == IntPtr.Zero) {
				throw new Exception("Header or data null after pcap read");
			}

			pcap_pkthdr pkt_header = (pcap_pkthdr) Marshal.PtrToStructure(_header, typeof(pcap_pkthdr));
			if (pkt_header.caplen != pkt_header.len || pkt_header.caplen > size) {
				throw new Exception("Incoming packet didn't fit into the buffer provided");
			}
			Marshal.Copy(_data, buffer, offset, (int) pkt_header.caplen);

			return (int) pkt_header.caplen;
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

