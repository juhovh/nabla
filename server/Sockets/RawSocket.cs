/**
 *  NABLA - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Collections.Generic;

using System.Reflection;
using System.Collections;

namespace Nabla.Sockets {
	public abstract class RawSocket {
		private string _ifname;

		public RawSocket(string ifname) {
			_ifname = ifname;
		}

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
		public abstract int SendTo(byte[] buffer, int offset, int size, IPEndPoint remoteEP);

		public int SendTo(byte[] buffer, int size, IPEndPoint remoteEP) {
			return SendTo(buffer, 0, size, remoteEP);
		}
		public int SendTo(byte[] buffer, IPEndPoint remoteEP) {
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
		public abstract int ReceiveFrom(byte[] buffer, int offset, int size, ref IPEndPoint remoteEP);

		public int ReceiveFrom(byte[] buffer, int size, ref IPEndPoint remoteEP) {
			return ReceiveFrom(buffer, 0, buffer.Length, ref remoteEP);
		}
		public int ReceiveFrom(byte[] buffer, ref IPEndPoint remoteEP) {
			return ReceiveFrom(buffer, buffer.Length, ref remoteEP);
		}
		public int Receive(byte[] buffer, int offset, int size) {
			IPEndPoint endPoint = null;
			return ReceiveFrom(buffer, offset, size, ref endPoint);
		}
		public int Receive(byte[] buffer, int size) {
			return Receive(buffer, 0, size);
		}
		public int Receive(byte[] buffer) {
			return Receive(buffer, buffer.Length);
		}

		public byte[] GetHardwareAddress() {
			return GetHardwareAddress(_ifname);
		}

		public Dictionary<IPAddress, IPAddress> GetIPAddresses() {
			return GetIPAddresses(_ifname);
		}

		public static byte[] GetHardwareAddress(string ifname) {
			byte[] retaddr = null;

			if (Type.GetType("System.Management.ManagementObject") != null) {
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
				try {
					return RawSocketNative.GetHardwareAddress(ifname);
				} catch (Exception) {}

				try {
					return RawSocketPcap.GetHardwareAddress(ifname);
				} catch (Exception) {}

				throw new Exception("Error getting hardware address for interface " + ifname);
			}

			return retaddr;
		}

		public static Dictionary<IPAddress, IPAddress> GetIPAddresses(string ifname) {
			try {
				return RawSocketNative.GetIPAddresses(ifname);
			} catch (Exception) {}

			try {
				return RawSocketPcap.GetIPAddresses(ifname);
			} catch (Exception) {}

			throw new Exception("Error getting IP addresses for interface " + ifname);
		}
	}
}

