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

namespace Nabla {
	public class NATPacket {
		private byte[] _bytes;
		private Byte _hlen;
		private UInt16 _datalen;
		public readonly ProtocolType ProtocolType;

		public NATPacket(byte[] data) : this(data, 0, data.Length) {
		}

		public NATPacket(byte[] data, int length) : this(data, 0, length) {
		}

		public NATPacket(byte[] data, int index, int length) {
			_bytes = new byte[length];
			Array.Copy(data, index, _bytes, 0, length);

			_hlen = (byte) ((_bytes[0] & 0x0f) * 4);
			_datalen = (UInt16) ((_bytes[2] << 8 | _bytes[3]) - _hlen);
			ProtocolType = (ProtocolType) _bytes[9];
		}

		public IPAddress SourceAddress {
			get {
				/* XXX: Check that it's an IPv4 address */
				byte[] addr = new byte[4];
				Array.Copy(_bytes, 12, addr, 0, 4);
				return new IPAddress(addr);
			}
			set {
				/* XXX: Check that it's an IPv4 address */
				Array.Copy(value.GetAddressBytes(), 0,
					   _bytes, 12, 4);
			}
		}

		public IPAddress DestinationAddress {
			get {
				/* XXX: Check that it's an IPv4 address */
				byte[] addr = new byte[4];
				Array.Copy(_bytes, 16, addr, 0, 4);
				return new IPAddress(addr);
			}
			set {
				/* XXX: Check that it's an IPv4 address */
				Array.Copy(value.GetAddressBytes(), 0,
					   _bytes, 16, 4);
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

				_bytes[_hlen+4] = (byte) (value >> 8);
				_bytes[_hlen+5] = (byte) value;
			}
		}

		public UInt16 GetNatID(bool external) {
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

		public void SetNatID(UInt16 value, bool external) {
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
				recalculateChecksums();
				return _bytes;
			}
		}

		public bool Supported {
			get {
				if (ProtocolType == ProtocolType.Tcp ||
				    ProtocolType == ProtocolType.Udp ||
				    ProtocolType == ProtocolType.Icmp) {
					return true;
				} else {
					return false;
				}
			}
		}

		private void recalculateChecksums() {
			_bytes[10] = _bytes[11] = 0;

			int checksum = 0;
			for (int i=0; i<_hlen; i++)
				checksum += _bytes[i] << ((i%2 == 0)?8:0);
			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;

			_bytes[10] = (byte) (checksum >> 8);
			_bytes[11] = (byte) (checksum);

			if (ProtocolType == ProtocolType.Tcp) {
				_bytes[_hlen+16] = _bytes[_hlen+17] = 0;
				checksum = pseudoHeaderChecksum();
			} else if (ProtocolType == ProtocolType.Udp) {
				_bytes[_hlen+6] = _bytes[_hlen+7] = 0;
				checksum = pseudoHeaderChecksum();
			} else if (ProtocolType == ProtocolType.Icmp) {
				_bytes[_hlen+2] = _bytes[_hlen+3] = 0;
				checksum = 0;
			} else {
				throw new Exception("Unsupported protocol type");
			}

			for (int i=0; i<_datalen; i++) {
				checksum += _bytes[_hlen+i] << ((i%2 == 0)?8:0);
			}
			if (checksum > 0xffff)
				checksum = (checksum & 0xffff) + (checksum >> 16);
			checksum = ~checksum;

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
		}

		private int pseudoHeaderChecksum() {
			int checksum = 0;

			/* Source and destination address */
			for (int i=0; i<8; i++)
				checksum += _bytes[12+i] << ((i%2 == 0)?8:0);
			checksum += (Byte) ProtocolType;
			checksum += _datalen;

			return checksum;
		}
	}
}
