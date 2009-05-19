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
using System.Runtime.InteropServices;

using System.Reflection;
using System.Collections;

namespace Nabla {
	public abstract class RawSocket {
		[DllImport("rawsock")]
		private static extern int rawsock_get_hardware_address(string ifname, byte[] address, ref int addrlen, ref int err);

		public static RawSocket GetRawSocket(string ifname, AddressFamily addressFamily, int protocol, int waitms) {
			try {
				if (Environment.OSVersion.Platform == PlatformID.Unix) {
					return new RawSocketNative(ifname, addressFamily, protocol, waitms);
				}
			} catch (Exception) {
			}

			return new RawSocketPcap(ifname, addressFamily, protocol, waitms);
		}

		public static RawSocket GetRawSocket(AddressFamily addressFamily, int protocol, int waitms) {
			return GetRawSocket(null, addressFamily, protocol, waitms);
		}

		public static RawSocket GetRawSocket(AddressFamily addressFamily, int protocol) {
			return GetRawSocket(addressFamily, protocol, 100);
		}

		public abstract void Bind(EndPoint localEP);

		public abstract bool WaitForWritable();
		public abstract int SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP);

		public int SendTo(byte[] buffer, int size, EndPoint remoteEP) {
			return SendTo(buffer, 0, size, remoteEP);
		}
		public int SendTo(byte[] buffer, EndPoint remoteEP) {
			return SendTo(buffer, buffer.Length, remoteEP);
		}
		public int Send(byte[] buffer, int offset, int size) {
			return SendTo(buffer, offset, size, null);
		}
		public int Send(byte[] buffer, int size) {
			return Send(buffer, 0, size);
		}
		public int Send(byte[] buffer) {
			return Send(buffer, buffer.Length);
		}

		public abstract bool WaitForReadable();
		public abstract int ReceiveFrom(byte[] buffer, int offset, int size, ref EndPoint remoteEP);

		public int ReceiveFrom(byte[] buffer, int size, ref EndPoint remoteEP) {
			return ReceiveFrom(buffer, 0, size, ref remoteEP);
		}
		public int ReceiveFrom(byte[] buffer, ref EndPoint remoteEP) {
			return ReceiveFrom(buffer, buffer.Length, ref remoteEP);
		}
		public int Receive(byte[] buffer, int offset, int size) {
			EndPoint endPoint = null;
			return ReceiveFrom(buffer, offset, size, ref endPoint);
		}
		public int Receive(byte[] buffer, int size) {
			return Receive(buffer, 0, size);
		}
		public int Receive(byte[] buffer) {
			return Receive(buffer, buffer.Length);
		}

		public static byte[] GetHardwareAddress(string ifname) {
			byte[] retaddr = null;

			if (Environment.OSVersion.Platform != PlatformID.Unix) {
				string rtDir = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
				Assembly assembly = Assembly.LoadFile(rtDir + "System.Management.dll");

				Type mosType = assembly.GetType("System.Management.ManagementObjectSearcher");
				Type moType = assembly.GetType("System.Management.ManagementObject");

				string query = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=1";
				object mosObj = Activator.CreateInstance(mosType, new object[] { query });

				IEnumerable queryCollection;
				BindingFlags getFlags = BindingFlags.InvokeMethod;
				queryCollection = (IEnumerable) mosType.InvokeMember("Get", getFlags, null, mosObj, null);

				foreach (object moObj in queryCollection) {
					BindingFlags itemFlags = BindingFlags.GetProperty;

					object caption = moType.InvokeMember("Item", itemFlags, null, moObj, new object[] { "Caption" });
					object mac = moType.InvokeMember("Item", itemFlags, null, moObj, new object[] { "MACAddress" });
					if (caption == null || mac == null)
						continue;

					/* XXX: This cuts the index away, should be probably tested more? */
					caption = caption.ToString().Substring(11);
					Console.WriteLine("Name: \"{0}\" Address: \"{1}\"", caption, mac);

					if (ifname.IndexOf(caption.ToString()) == 0 && mac.ToString().Length == 17) {
						retaddr = new byte[6];
						for (int i=0; i<6; i++) {
							retaddr[i] = Byte.Parse(mac.ToString().Substring(i*3, 2),
								System.Globalization.NumberStyles.HexNumber);
						}
					}
				}
			} else {
				byte[] address = new byte[6];
				int addrlen = 6;
				int ret, err = 0;

				ret = rawsock_get_hardware_address(ifname, address, ref addrlen, ref err);
				if (ret == -1) {
					throw new Exception("Error getting hardware address");
				}

				retaddr = new byte[addrlen];
				Array.Copy(address, 0, retaddr, 0, addrlen);
			}

			return retaddr;
		}
	}
}

