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
using System.Net;
using System.Net.Sockets;

namespace Nabla {
	public class NATPacket {
		private byte[] _bytes;
		private Byte _hlen;
		private int _ipchecksum;
		private int _checksum;

		public readonly ProtocolType ProtocolType;

		public NATPacket(byte[] data) : this(data, 0, data.Length) {
		}

		public NATPacket(byte[] data, int length) : this(data, 0, length) {
		}

		public NATPacket(byte[] data, int index, int length) {
			_bytes = new byte[length];
			Array.Copy(data, index, _bytes, 0, length);

			_hlen = (byte) ((_bytes[0] & 0x0f) * 4);
			ProtocolType = (ProtocolType) _bytes[9];

			_ipchecksum = 0xffff & ~(_bytes[10]*256 + _bytes[11]);
			if (ProtocolType == ProtocolType.Tcp) {
				_checksum = 0xffff & ~(_bytes[_hlen+16]*256 + _bytes[_hlen+17]);
			} else if (ProtocolType == ProtocolType.Udp) {
				_checksum = 0xffff & ~(_bytes[_hlen+6]*256 + _bytes[_hlen+7]);
			} else if (ProtocolType == ProtocolType.Icmp) {
				_checksum = 0xffff & ~(_bytes[_hlen+2]*256 + _bytes[_hlen+3]);
			} else {
				throw new Exception("Unsupported protocol type");
			}
		}

		public IPAddress SourceAddress {
			get {
				byte[] addr = new byte[4];
				Array.Copy(_bytes, 12, addr, 0, 4);
				return new IPAddress(addr);
			}
			set {
				if (value.AddressFamily != AddressFamily.InterNetwork)
					throw new Exception("IPv4 address family required");

				int csmod = 0;
				byte[] addr = value.GetAddressBytes();
				csmod -= (_bytes[12]+_bytes[14])*256;
				csmod -= (_bytes[13]+_bytes[15]);
				csmod += (addr[0]+addr[2])*256;
				csmod += (addr[1]+addr[3]);
				if (csmod <= 0) {
					/* This can never be less than -0x1fffe */
					csmod = (csmod - 1) & 0xffff;
				}

				/* Modify the IPv4 header checksum */
				_ipchecksum += csmod;

				if (ProtocolType != ProtocolType.Icmp) {
					/* Modify the transport protocol checksum */
					_checksum += csmod;
				}

				/* Copy new address data in place of the old one */
				Array.Copy(value.GetAddressBytes(), 0, _bytes, 12, 4);
			}
		}

		public IPAddress DestinationAddress {
			get {
				byte[] addr = new byte[4];
				Array.Copy(_bytes, 16, addr, 0, 4);
				return new IPAddress(addr);
			}
			set {
				if (value.AddressFamily != AddressFamily.InterNetwork)
					throw new Exception("IPv4 address family required");

				int csmod = 0;
				byte[] addr = value.GetAddressBytes();
				csmod -= (_bytes[16]+_bytes[18])*256;
				csmod -= (_bytes[17]+_bytes[19]);
				csmod += (addr[0]+addr[2])*256;
				csmod += (addr[1]+addr[3]);
				if (csmod <= 0) {
					/* This can never be less than -0x1fffe */
					csmod = (csmod - 1) & 0xffff;
				}

				/* Modify the IPv4 header checksum */
				_ipchecksum += csmod;

				if (ProtocolType != ProtocolType.Icmp) {
					/* Modify the transport protocol checksum */
					_checksum += csmod;
				}

				/* Copy new address data in place of the old one */
				Array.Copy(value.GetAddressBytes(), 0, _bytes, 16, 4);
			}
		}

		public UInt16 SourcePort {
			get {
				if (ProtocolType != ProtocolType.Tcp &&
				    ProtocolType != ProtocolType.Udp)
					throw new Exception("Source port not available");

				return (UInt16) (_bytes[_hlen+0] << 8 | _bytes[_hlen+1]);
			}
			set {
				if (ProtocolType != ProtocolType.Tcp &&
				    ProtocolType != ProtocolType.Udp)
					throw new Exception("Source port not available");

				/* Modify the transport protocol checksum */
				_checksum -= _bytes[_hlen]*256 + _bytes[_hlen+1];
				_checksum += value;
				if (_checksum <= 0) {
					_checksum = (_checksum - 1) & 0xffff;
				}

				_bytes[_hlen]   = (byte) (value >> 8);
				_bytes[_hlen+1] = (byte) value;
			}
		}

		public UInt16 DestinationPort {
			get {
				if (ProtocolType != ProtocolType.Tcp &&
				    ProtocolType != ProtocolType.Udp)
					throw new Exception("Destination port not available");

				return (UInt16) (_bytes[_hlen+2] << 8 | _bytes[_hlen+3]);
			}
			set {
				if (ProtocolType != ProtocolType.Tcp &&
				    ProtocolType != ProtocolType.Udp)
					throw new Exception("Destination port not available");

				/* Modify the transport protocol checksum */
				_checksum -= _bytes[_hlen+2]*256 + _bytes[_hlen+3];
				_checksum += value;
				if (_checksum <= 0) {
					_checksum = (_checksum - 1) & 0xffff;
				}

				_bytes[_hlen+2] = (byte) (value >> 8);
				_bytes[_hlen+3] = (byte) value;
			}
		}

		public Byte IcmpType {
			get {
				if (ProtocolType != ProtocolType.Icmp)
					throw new Exception("ICMP type not available");

				return _bytes[_hlen];
			}
			set {
				if (ProtocolType != ProtocolType.Icmp)
					throw new Exception("ICMP type not available");

				/* Modify the ICMP checksum */
				_checksum -= _bytes[_hlen]*256;
				_checksum += value*256;
				if (_checksum <= 0) {
					_checksum = (_checksum - 1) & 0xffff;
				}

				_bytes[_hlen] = value;
			}
		}

		public UInt16 IcmpID {
			get {
				if (ProtocolType != ProtocolType.Icmp)
					throw new Exception("ICMP identifier not available");

				return (UInt16) (_bytes[_hlen+4] << 8 | _bytes[_hlen+5]);
			}
			set {
				if (ProtocolType != ProtocolType.Icmp)
					throw new Exception("ICMP identifier not available");

				/* Modify the ICMP checksum */
				_checksum -= _bytes[_hlen+4]*256 + _bytes[_hlen+5];
				_checksum += value;
				if (_checksum <= 0) {
					_checksum = (_checksum - 1) & 0xffff;
				}

				_bytes[_hlen+4] = (byte) (value >> 8);
				_bytes[_hlen+5] = (byte) value;
			}
		}

		public UInt16 IntNatID {
			get {
				return GetNatID(false);
			}
			set {
				SetNatID(value, false);
			}
		}

		public UInt16 ExtNatID {
			get {
				return GetNatID(true);
			}
			set {
				SetNatID(value, true);
			}
		}

		private UInt16 GetNatID(bool external) {
			if (ProtocolType == ProtocolType.Tcp ||
			    ProtocolType == ProtocolType.Udp) {
				if (external)
					return this.DestinationPort;
				else
					return this.SourcePort;
			} else if (ProtocolType == ProtocolType.Icmp) {
				return this.IcmpID;
			} else {
				throw new Exception("NAT identifier not available");
			}
		}

		private void SetNatID(UInt16 value, bool external) {
			if (ProtocolType == ProtocolType.Tcp ||
			    ProtocolType == ProtocolType.Udp) {
				if (external)
					this.DestinationPort = value;
				else
					this.SourcePort = value;
			} else if (ProtocolType == ProtocolType.Icmp) {
				this.IcmpID = value;
			} else {
				throw new Exception("NAT identifier not available");
			}
		}

		public byte[] Bytes {
			get {
				int checksum;

				/* Set the IP level protocol checksum */
				while (_ipchecksum > 0xffff) {
					_ipchecksum = (_ipchecksum & 0xffff) +
					              (_ipchecksum >> 16);
				}
				checksum = ~_ipchecksum;
				_bytes[10] = (byte) (checksum >> 8);
				_bytes[11] = (byte) (checksum);

				/* Set the transport level protocol checksum */
				while (_checksum > 0xffff) {
					_checksum = (_checksum & 0xffff) +
					            (_checksum >> 16);
				}
				checksum = ~_checksum;
				if (ProtocolType == ProtocolType.Tcp) {
					_bytes[_hlen+16] = (byte) (checksum >> 8);
					_bytes[_hlen+17] = (byte) (checksum);
				} else if (ProtocolType == ProtocolType.Udp) {
					_bytes[_hlen+6] = (byte) (checksum >> 8);
					_bytes[_hlen+7] = (byte) (checksum);
				} else if (ProtocolType == ProtocolType.Icmp) {
					_bytes[_hlen+2] = (byte) (checksum >> 8);
					_bytes[_hlen+3] = (byte) (checksum);
				}

				return _bytes;
			}
		}
	}
}
