using System;
using System.Net;
using Nabla.Database;

public class CreateDatabase {
	private static void Main(string[] args) {
		if (args.Length != 1) {
			Console.WriteLine("Requires database filename argument");
			return;
		}

		using (UserDatabase userDB = new UserDatabase(args[0])) {
			userDB.CreateTables();

			UserInfo userInfo = new UserInfo();
			userInfo.UserName = "juhovh";
			userInfo.Password = "salasana";
			userInfo.TunnelPassword = "sanasala";
			userInfo.FullName = "Juho Vähä-Herttua";
			userDB.AddUserInfo(userInfo);

			Console.WriteLine("Password correct: " + userDB.ValidatePassword("juhovh", "salasana"));
		}

		using (TICDatabase TicDB = new TICDatabase(args[0])) {
			TicDB.CreateTables();

			TICUserInfo userInfo = new TICUserInfo();
			userInfo.UserName = "juhovh";
			userInfo.Password = "testi";
			userInfo.FullName = "Juho Vähä-Herttua";
			TicDB.AddUserInfo(userInfo);

			/* This is to get the user ID correctly */
			userInfo = TicDB.GetUserInfo(userInfo.UserName);

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
			TicDB.AddTunnelInfo(tunnelInfo);

			/* This is to get the tunnel ID correctly */
			tunnelInfo = TicDB.ListTunnels(userInfo.UserId)[0];

			TICRouteInfo routeInfo = new TICRouteInfo();
			routeInfo.OwnerId = userInfo.UserId;
			routeInfo.TunnelId = tunnelInfo.TunnelId;
			routeInfo.IPv6Prefix = IPAddress.Parse("fec1::");
			routeInfo.IPv6PrefixLength = 64;
			routeInfo.Description = "This is a default route for a subnet";
			TicDB.AddRouteInfo(routeInfo);

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
			TicDB.AddPopInfo(popInfo);
		}
	}
}

