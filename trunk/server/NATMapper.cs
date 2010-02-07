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
	public class NATMapping {
		public readonly ProtocolType Protocol;
		public DateTime LastActive;

		public readonly IPAddress InternalAddress;
		public readonly UInt16 InternalID;

		public IPAddress ExternalAddress;
		public UInt16 ExternalID;

		public NATMapping(ProtocolType protocol,
				  IPAddress internalIP,
				  UInt16 id) {
			Protocol = protocol;
			InternalAddress = internalIP;
			InternalID = id;
		}
	}

	public class NATAddressList {
		private List<IPAddress> _list;

		public NATAddressList() {
			_list = new List<IPAddress>();
		}

		private NATAddressList(List<IPAddress> list) {
			_list = list;
		}

		public IPAddress this[int index] {
			get {
				return _list[index];
			}
		}

		public static NATAddressList operator +(NATAddressList list, IPAddress address) {
			List<IPAddress> tmplist = new List<IPAddress>(list._list);
			tmplist.Add(address);
			return new NATAddressList(tmplist);
		}
	}

	public class NATMapper {
		private Dictionary<ProtocolType, Dictionary<UInt16, List<NATMapping>>> _intMap
			= new Dictionary<ProtocolType, Dictionary<UInt16, List<NATMapping>>>();
		private Dictionary<ProtocolType, Dictionary<UInt16, NATMapping>> _extMap
			= new Dictionary<ProtocolType, Dictionary<UInt16, NATMapping>>();
		public NATAddressList Addresses = new NATAddressList();

		public NATMapping GetIntMapping(ProtocolType type, IPAddress ipAddr, UInt16 port) {
			try {
				foreach (NATMapping m in _intMap[type][port]) {
					if (ipAddr.Equals(m.InternalAddress)) {
						m.LastActive = DateTime.Now;
						return m;
					}
				}
			} catch (KeyNotFoundException) {
			}

			return null;
		}

		public NATMapping GetExtMapping(ProtocolType type, UInt16 port) {
			try {
				return _extMap[type][port];
			} catch (KeyNotFoundException) {
				return null;
			}
		}

		public void AddProtocol(ProtocolType t) {
			if (_intMap.ContainsKey(t) || _extMap.ContainsKey(t))
				throw new Exception("Protocol already added");

			_intMap.Add(t, new Dictionary<UInt16, List<NATMapping>>());
			_extMap.Add(t, new Dictionary<UInt16, NATMapping>());
		}

		public void AddMapping(NATMapping m) {
			/* This shouldn't happen since getIntMapping should be checked first */
			if (GetIntMapping(m.Protocol, m.InternalAddress, m.InternalID) != null)
				throw new Exception("Internal ID already mapped");

			int externalID = -1;
			for (int i=0; i<65536; i++) {
				if (!_extMap[m.Protocol].ContainsKey((UInt16) (m.InternalID+i))) {
					externalID = (m.InternalID+i)&0xffff;
					break;
				}
			}
			if (externalID == -1)
				throw new Exception("Couldn't find external port, ran out of ports?");

			m.ExternalAddress = Addresses[0];
			m.ExternalID = (UInt16) externalID;
			m.LastActive = DateTime.Now;

			if (!_intMap[m.Protocol].ContainsKey(m.InternalID))
				_intMap[m.Protocol].Add(m.InternalID, new List<NATMapping>());

			_intMap[m.Protocol][m.InternalID].Add(m);
			_extMap[m.Protocol].Add(m.ExternalID, m);
		}
	}
}


