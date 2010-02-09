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

namespace Nabla {
	public enum TunnelType {
		Unknown,
		IPv4inIPv4,
		IPv4inIPv6,
		IPv6inIPv4,
		IPv6inIPv6,
		HeartbeatIPv4,
		HeartbeatIPv6,
		AYIYAinIPv4,
		AYIYAinIPv6,
		IPv6inUDPv4,
		IPv6inUDPv6
	};
}
