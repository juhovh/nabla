using System;
using System.Net;
using System.Net.Sockets;
using Nabla;

public class TSPServerTest {
	private static void Main(string[] args) {
		TSPServer server = new TSPServer();
		server.Start();
	}
}

