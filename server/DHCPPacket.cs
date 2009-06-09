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

namespace Nabla {
	public class DHCPPacket {
		public Byte OP { get; private set; }
		public Byte HTYPE { get; private set; }
		public Byte HLEN { get; private set; }
		public Byte HOPS { get; private set; }

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

		public byte[] _chaddr;
		public byte[] CHADDR {
			get {
				if (HLEN > 16) {
					throw new Exception("HLEN too long");
				}
				byte[] ret = new byte[HLEN];
				Array.Copy(_chaddr, 0, ret, 0, HLEN);
				return ret;
			}
			set {
				if (value.Length != HLEN) {
					throw new Exception("Address length incorrect");
				}
				Array.Copy(value, 0, _chaddr, 0, HLEN);
			}
		}

		public byte[] Data {
			get {
				/* XXX: Get options */
				int optionSize = 0;
				byte[] ret = new byte[240 + optionSize];
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
				Array.Copy(_chaddr, 0, ret, 28, 16);

				/* SNAME and FILE fields can be null, 192 bytes */

				/* Add the DHCP magic cookie */
				ret[236] = 99;
				ret[237] = 130;
				ret[238] = 83;
				ret[239] = 99;

				return ret;
			}
			set {
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

				Array.Copy(value, 28, _chaddr, 0, 16);

				/* SNAME and FILE fields can be ignored */

				/* XXX: Parse the DHCP options */
			}
		}
	}
}
