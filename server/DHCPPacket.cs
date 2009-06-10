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
using System.Collections.Generic;

namespace Nabla {
	public class DHCPOption {
		public readonly byte Code;
		public readonly byte[] Data;

		public DHCPOption(byte code, byte[] data) {
			Code = code;
			Data = data;
		}
	}

	public enum DHCPType : byte {
		DHCPDISCOVER = 1,
		DHCPOFFER    = 2,
		DHCPREQUEST  = 3,
		DHCPDECLINE  = 4,
		DHCPACK      = 5,
		DHCPNAK      = 7,
		DHCPRELEASE  = 8
	}

	public class DHCPPacket {
		public byte OP { get; private set; }
		public byte HTYPE { get; private set; }
		public byte HLEN { get; private set; }
		public byte HOPS { get; private set; }

		public UInt32 XID;
		public UInt16 SECS;
		public UInt16 FLAGS { get; private set; }
		public bool Broadcast {
			get {
				return ((FLAGS & 0x8000) != 0);
			}
			set {
				if (value) {
					FLAGS |= 0x8000;
				} else {
					FLAGS &= 0x7fff;
				}
			}
		}

		public IPAddress CIADDR = IPAddress.Any;
		public IPAddress YIADDR = IPAddress.Any;
		public IPAddress SIADDR = IPAddress.Any;
		public IPAddress GIADDR = IPAddress.Any;
		public readonly byte[] CHADDR = new byte[16];

		private List<DHCPOption> _options = new List<DHCPOption>();
		public void AddOption(DHCPOption option) {
			_options.Add(option);
		}
		public DHCPOption FindOption(byte code) {
			foreach (DHCPOption o in _options) {
				if (o.Code == code)
					return o;
			}
			return null;
		}

		private DHCPPacket() {
		}

		public DHCPPacket(DHCPType type) {
			switch (type) {
			case DHCPType.DHCPDISCOVER:
			case DHCPType.DHCPREQUEST:
			case DHCPType.DHCPDECLINE:
			case DHCPType.DHCPRELEASE:
				OP = 0x01;
				break;
			case DHCPType.DHCPOFFER:
			case DHCPType.DHCPACK:
			case DHCPType.DHCPNAK:
				OP = 0x02;
				break;
			}

			/* Set some defaults */
			HTYPE = 0x01;
			HLEN = 0x06;
			HOPS = 0x00;
			XID = 0x3903F326; // XXX: Should randomize

			/* Add DHCP type option */
			AddOption(new DHCPOption(53, new byte[] { (byte) type }));
		}

		public static DHCPPacket Parse(byte[] data, int offset, int length) {
			DHCPPacket ret = new DHCPPacket();

			byte[] tmpdata = new byte[length];
			Array.Copy(data, offset, tmpdata, 0, length);
			ret.Data = tmpdata;

			return ret;
		}

		public static DHCPPacket GetDiscoverPacket(byte[] hwaddr) {
			DHCPPacket packet = new DHCPPacket(DHCPType.DHCPDISCOVER);
			Array.Copy(hwaddr, 0, packet.CHADDR, 0, hwaddr.Length);
			return packet;
		}

		public byte[] GetIPv4Bytes(IPAddress source, IPAddress dest) {
			byte[] dhcpData = this.Data;
			byte[] data = new byte[20 + 8 + dhcpData.Length];

			data[0] = 0x45;
			data[2] = (byte) (data.Length >> 8);
			data[3] = (byte) (data.Length);
			data[8] = 64; // TTL 64
			data[9] = 17; // Protocol UDP
			Array.Copy(source.GetAddressBytes(), 0, data, 12, 4);
			Array.Copy(dest.GetAddressBytes(), 0, data, 16, 4);

			if (OP == 0x01) {
				/* Client to server packet */
				data[21] = 68;
				data[23] = 67;
			} else if (OP == 0x02) {
				/* Server to client packet */
				data[21] = 67;
				data[23] = 68;
			}

			data[24] = (byte) ((dhcpData.Length + 8) >> 8);
			data[25] = (byte) (dhcpData.Length + 8);

			Array.Copy(dhcpData, 0, data, 28, dhcpData.Length);

			calculateIPv4Checksum(data);
			calculateUDPChecksum(data);

			return data;
		}

		private void calculateIPv4Checksum(byte[] data) {
			int length = (data[0] & 0x0f) * 4;

			int checksum = 0;
			data[10] = data[11] = 0;
			for (int i=0; i<length; i++)
				checksum += data[i] << ((i%2 == 0)?8:0);

			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;
			data[10] = (byte) (checksum >> 8);
			data[11] = (byte) (checksum);
		}

		private void calculateUDPChecksum(byte[] data) {
			int startidx = (data[0] & 0x0f) * 4;
			int length = (data[startidx+4] << 8) | data[startidx+5];

			int checksum = 0;
			data[startidx+6] = data[startidx+7] = 0;
			checksum += data[9];
			checksum += length;
			for (int i=12; i<20; i++)
				checksum += data[i] << ((i%2 == 0)?8:0);
			for (int i=0; i<length; i++)
				checksum += data[startidx+i] << ((i%2 == 0)?8:0);

			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;
			data[startidx+6] = (byte) (checksum >> 8);
			data[startidx+7] = (byte) (checksum);
		}

		public byte[] Data {
			get {
				int optionsSize = 0;
				foreach (DHCPOption o in _options) {
					optionsSize += 2 + o.Data.Length;
				}

				byte[] ret = new byte[240 + optionsSize];
				ret[0] = OP;
				ret[1] = HTYPE;
				ret[2] = HLEN;
				ret[3] = HOPS;
				ret[4] = (byte) (XID >> 24);
				ret[5] = (byte) (XID >> 16);
				ret[6] = (byte) (XID >> 8);
				ret[7] = (byte)  XID;
				ret[8] = (byte) (SECS >> 8);
				ret[9] = (byte)  SECS;
				ret[10] = (byte) (FLAGS >> 8);
				ret[11] = (byte)  FLAGS;

				Array.Copy(CIADDR.GetAddressBytes(), 0, ret, 12, 4);
				Array.Copy(YIADDR.GetAddressBytes(), 0, ret, 16, 4);
				Array.Copy(SIADDR.GetAddressBytes(), 0, ret, 20, 4);
				Array.Copy(GIADDR.GetAddressBytes(), 0, ret, 24, 4);
				Array.Copy(CHADDR, 0, ret, 28, 16);

				/* SNAME and FILE fields can be null, 192 bytes */

				/* Add the DHCP magic cookie */
				ret[236] = 99;
				ret[237] = 130;
				ret[238] = 83;
				ret[239] = 99;

				int index = 240;
				foreach (DHCPOption o in _options) {
					ret[index++] = o.Code;
					ret[index++] = (byte) o.Data.Length;

					Array.Copy(o.Data, 0, ret, index, o.Data.Length);
					index += o.Data.Length;
				}

				return ret;
			}
			private set {
				if (value.Length < 240) {
					throw new Exception("Length not enough for DHCP packet");
				}

				if (value[236] != 99 || value[237] != 130 ||
				    value[238] != 83 || value[239] != 99) {
					throw new Exception("DHCP magic cookie not found");
				}

				OP    = value[0];
				HTYPE = value[1];
				HLEN  = value[2];
				HOPS  = value[3];

				XID = (UInt32) ((value[4] << 24) | (value[5] << 16) | (value[6] << 8) | value[7]);
				SECS = (UInt16) ((value[8] << 8) | value[9]);
				FLAGS = (UInt16) ((value[10] << 8) | value[11]);

				byte[] ipaddress = new byte[4];
				Array.Copy(value, 12, ipaddress, 0, 4);
				CIADDR = new IPAddress(ipaddress);
				Array.Copy(value, 16, ipaddress, 0, 4);
				YIADDR = new IPAddress(ipaddress);
				Array.Copy(value, 20, ipaddress, 0, 4);
				SIADDR = new IPAddress(ipaddress);
				Array.Copy(value, 24, ipaddress, 0, 4);
				GIADDR = new IPAddress(ipaddress);

				Array.Copy(value, 28, CHADDR, 0, 16);

				/* SNAME and FILE fields can be ignored */

				int index = 240;
				while (index < value.Length) {
					if (value[index] == 0) {
						index++;
						continue;
					}

					int len = value[index+1];
					byte[] data = new byte[len];
					Array.Copy(value, index+2, data, 0, len);
					DHCPOption option = new DHCPOption(value[index], data);
					this.AddOption(option);
					index += 2 + len;
				}
			}
		}
	}
}
