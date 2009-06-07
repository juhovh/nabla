using System;
using System.Net;
using Nabla.Database;

public class TICDatabaseCreate {
	private static void Main(string[] args) {
		if (args.Length != 1) {
			Console.WriteLine("Requires database filename argument");
			return;
		}

		TICDatabase db = new TICDatabase(args[0]);
		db.CreateTables();

		TICUserInfo userInfo = new TICUserInfo();
		userInfo.UserName = "juhovh";
		userInfo.Password = "testi";
		userInfo.FullName = "Juho Vähä-Herttua";
		db.AddUserInfo(userInfo);

		/* This is to get the user ID correctly */
		userInfo = db.GetUserInfo(userInfo.UserName);

		TICTunnelInfo tunnelInfo = new TICTunnelInfo();
		tunnelInfo.OwnerId = userInfo.UserId;
		tunnelInfo.IPv6Endpoint = IPAddress.Parse("fec0::2");
		tunnelInfo.IPv6POP = IPAddress.Parse("fec0::1");
		tunnelInfo.IPv6PrefixLength = 64;
		tunnelInfo.TunnelMTU = 1280;
		tunnelInfo.TunnelName = "Tunnel name foo";
		tunnelInfo.POPId = "popid01";
		tunnelInfo.IPv4Endpoint = "ayiya";
		tunnelInfo.IPv4POP = IPAddress.Parse("192.168.1.10");
		tunnelInfo.Password = "salasana";
		tunnelInfo.HeartbeatInterval = 60;
		db.AddTunnelInfo(tunnelInfo);

		/* This is to get the tunnel ID correctly */
		tunnelInfo = db.ListTunnels(userInfo.UserId)[0];

		TICRouteInfo routeInfo = new TICRouteInfo();
		routeInfo.OwnerId = userInfo.UserId;
		routeInfo.TunnelId = tunnelInfo.TunnelId;
		routeInfo.IPv6Prefix = IPAddress.Parse("fec1::");
		routeInfo.IPv6PrefixLength = 64;
		routeInfo.Description = "This is a default route for a subnet";
		db.AddRouteInfo(routeInfo);

		TICPopInfo popInfo = new TICPopInfo();
		popInfo.POPId = "popid01";
		popInfo.City = "Beijing";
		popInfo.Country = "China";
		popInfo.IPv4 = IPAddress.Parse("192.168.1.10");
		popInfo.IPv6 = IPAddress.Parse("2001::1");
		popInfo.HeartbeatSupport = true;
		popInfo.TincSupport = false;
		popInfo.MulticastSupport = "N";
		popInfo.ISPShort = "BUPT";
		popInfo.ISPName = "Beijing University of Posts and Telecommunications";
		popInfo.ISPWebsite = "http://www.bupt.edu.cn/";
		popInfo.ISPASNumber = 1234;
		popInfo.ISPLIRId = "id.test";
		db.AddPopInfo(popInfo);

		db.Cleanup();
	}
}

