using System;
using System.Net.Sockets;
using Nabla;
using Nabla.Sockets;

public class ParallelDeviceTest {
	private static void Main(string[] args) {
		if (args.Length < 1) {
			Console.WriteLine("Give the interface name as an argument");
			return;
		}

		ParallelDevice device = new ParallelDevice(args[0]);
		device.Start();
	}
}

