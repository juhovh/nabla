using System;
using System.Net;
using System.Net.Sockets;
using Nabla;

public class ParallelDeviceTest {
	private static void Main(string[] args) {
		Console.WriteLine("Date: " + DateTime.Now);
		TICServer server = new TICServer();
		server.Start();
	}
}

