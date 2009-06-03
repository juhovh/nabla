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
using System.Threading;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Nabla.Sockets;

namespace Nabla {
	public class Server {
		private IntDevice _intDevice;
		private ExtDevice _extDevice;

		public Server(string intName, string extName, TunnelType type) {
			_intDevice = new IntDevice(intName, type, new IntDeviceCallback(intReceive));
			_extDevice = new ExtDevice(extName, new ExtDeviceCallback(extReceive));
		}

		public void Start() {
			_intDevice.Start();
			_extDevice.Start();
		}

		public void Stop() {
			_intDevice.Stop();
			_extDevice.Stop();
		}

		private void intReceive(TunnelType type, IPEndPoint source, byte[] data) {
			_extDevice.SendPacket(source, data);
		}

		private void extReceive(IPEndPoint destination, byte[] data) {
			_intDevice.SendPacket(destination, data);
		}

		private static void Main(string[] args) {
			if (args.Length != 2) {
				Console.WriteLine("Invalid number of arguments\n");
				return;
			}

			Server server = new Server(args[0], args[1], TunnelType.IPv4inIPv6);
			server.Start();

			while (true) {
				Thread.Sleep(1000);
			}
		}
	}
}
