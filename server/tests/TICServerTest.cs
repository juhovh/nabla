using System;
using System.Net;
using System.Net.Sockets;
using Nabla;

public class TICServerTest {
	private static void Main(string[] args) {
		TICServer server = new TICServer();
		server.Start();
	}
}

