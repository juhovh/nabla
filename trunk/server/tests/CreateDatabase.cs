using System;
using System.Net;
using Nabla;
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
			userInfo.Enabled = true;
			userInfo.UserName = "juhovh";
			userInfo.Password = "salasana";
			userInfo.TunnelPassword = "sanasala";
			userInfo.FullName = "Juho Vähä-Herttua";
			userDB.AddUserInfo(userInfo);

			/* This is to get the user ID correctly */
			userInfo = userDB.GetUserInfo("juhovh");
			Console.WriteLine("Got user info\n-------------\n" + userInfo);
			Console.WriteLine("Password correct: " + userDB.ValidatePassword("juhovh", "salasana"));

			TunnelInfo tunnelInfo = new TunnelInfo();
			tunnelInfo.OwnerId = userInfo.UserId;
			tunnelInfo.Enabled = true;
			tunnelInfo.Name = "My first tunnel";
			tunnelInfo.Endpoint = "ayiya";
			tunnelInfo.UserEnabled = true;
			tunnelInfo.Password = "salasana";
			userDB.AddTunnelInfo(tunnelInfo);

			/* This is to get the tunnel ID correctly */
			tunnelInfo = userDB.ListTunnels(userInfo.UserId)[0];

			RouteInfo routeInfo = new RouteInfo();
			routeInfo.OwnerId = userInfo.UserId;
			routeInfo.TunnelId = tunnelInfo.TunnelId;
			routeInfo.Enabled = true;
			routeInfo.Description = "This is a default route for a subnet";
			routeInfo.UserEnabled = false;
			userDB.AddRouteInfo(routeInfo);
		}
	}
}

