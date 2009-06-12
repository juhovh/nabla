using System;
using System.Net;
using System.Net.Sockets;
using Nabla;

public class TICServerTest {
	private static void Main(string[] args) {
		SessionManager sessionManager = new SessionManager();
		InputDevice dev = new GenericInputDevice(args[0], GenericInputType.IPv6inIPv4);
		sessionManager.AddInputDevice(dev);
		sessionManager.AddOutputDevice(args[1], IPAddress.Parse("192.168.1.16"), true);
		sessionManager.Start();

		TICServer server = new TICServer(sessionManager);
		server.Start();
	}
}

