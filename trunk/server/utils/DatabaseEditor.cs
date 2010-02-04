using System;
using System.Net;
using Nabla;
using Nabla.Database;

public class DatabaseEditor {
	private static void Main(string[] args) {
		if (args.Length != 1) {
			Console.WriteLine("Requires database filename as an argument");
			return;
		}

		using (UserDatabase userDB = new UserDatabase(args[0])) {
			try {
				userDB.CreateTables();
			} catch (Exception) {
				// Tables probably already created, just ignore
			}

			while (true) {
				Console.WriteLine("Main menu:");
				Console.WriteLine("\t[1] Edit user accounts");
				Console.WriteLine("\t[2] Edit tunnels");
				Console.WriteLine("\t[0] Exit");
				Console.Write("Choose: ");

				string input = Console.ReadLine();
				try {
					int value = Convert.ToInt16(input);
					if (value == 0) {
						break;
					} else if (value == 1) {
						userMenu(userDB);
					} else if (value == 2) {
						tunnelMenu(userDB);
					} else {
						Console.WriteLine("Invalid choice: " + value);
					}
				} catch (Exception) {
					Console.WriteLine("Given input '" + input + "' not valid");
				}
			}
		}
	}

	private static void userMenu(UserDatabase userDB) {
		while (true) {
			Console.WriteLine("User account menu:");
			Console.WriteLine("\t[1] List user accounts");
			Console.WriteLine("\t[2] Add user account");
			Console.WriteLine("\t[3] Delete user account");
			Console.WriteLine("\t[0] Back to main menu");
			Console.Write("Choose: ");

			string input = Console.ReadLine();
			try {
				int value = Convert.ToInt16(input);
				if (value == 0) {
					break;
				} else if (value == 1) {
					listUserAccounts(userDB);
				} else if (value == 2) {
					addUserAccount(userDB);
				} else if (value == 3) {
					deleteUserAccount(userDB);
				} else {
					Console.WriteLine("Invalid choice: " + value);
				}
			} catch (Exception e) {
				Console.WriteLine("Given input '" + input + "' not valid");
				Console.WriteLine(e.ToString());
			}
		}
	}

	private static void tunnelMenu(UserDatabase userDB) {
		Console.Write("Username: ");
		string username = Console.ReadLine();
		UserInfo userInfo = userDB.GetUserInfo(username);

		if (userInfo == null) {
			Console.WriteLine("User '" + username + "' not found");
			return;
		}

		while (true) {
			Console.WriteLine("Tunnel menu for user '" + userInfo.UserName + "':");
			Console.WriteLine("\t[1] List tunnels");
			Console.WriteLine("\t[2] Add tunnel");
			Console.WriteLine("\t[3] Delete tunnel");
			Console.WriteLine("\t[0] Return to main menu");
			Console.Write("Choose: ");

			string input = Console.ReadLine();
			try {
				int value = Convert.ToInt16(input);
				if (value == 0) {
					break;
				} else if (value == 1) {
					listTunnels(userDB, userInfo.UserId);
				} else if (value == 2) {
					addTunnel(userDB, userInfo.UserId);
				} else {
					Console.WriteLine("Invalid choice: " + value);
				}
			} catch (Exception e) {
				Console.WriteLine("Given input '" + input + "' not valid");
				Console.WriteLine(e.ToString());
			}
		}
	}

	private static void listUserAccounts(UserDatabase userDB) {
		UserInfo[] users = userDB.ListUsers();

		Console.WriteLine("");
		Console.WriteLine("UserId | Username        | Full name");
		Console.WriteLine("-------------------------------------------------------------------");
		foreach (UserInfo userInfo in users) {
			string userid = "" + userInfo.UserId;
			string username = userInfo.UserName;
			string fullname = userInfo.FullName;

			for (int i=0; i<(6-userid.Length); i++)
				Console.Write(" ");
			Console.Write(userid);
			Console.Write(" | ");
			Console.Write(username);
			for (int i=0; i<(15-username.Length); i++)
				Console.Write(" ");

			Console.Write(" | ");
			Console.WriteLine(fullname);
		}
		Console.WriteLine("");
	}

	private static void addUserAccount(UserDatabase userDB) {
		string username;
		string fullname;
		string password;
		string tunnelPassword;

		Console.Write("Username: ");
		username = Console.ReadLine();

		Console.Write("Full name: ");
		fullname = Console.ReadLine();

		Console.Write("Master password: ");
		password = Console.ReadLine();

		Console.Write("Tunnel password: ");
		tunnelPassword = Console.ReadLine();

		UserInfo userInfo = new UserInfo();
		userInfo.Enabled = true;
		userInfo.UserName = username;
		userInfo.Password = password;
		userInfo.TunnelPassword = tunnelPassword;
		userInfo.FullName = fullname;
		userDB.AddUserInfo(userInfo);
	}

	private static void deleteUserAccount(UserDatabase userDB) {
	}

	private static void listTunnels(UserDatabase userDB, Int64 ownerId) {
		TunnelInfo[] tunnels = userDB.ListTunnels(ownerId);

		Console.WriteLine("");
		Console.WriteLine("TunnelId | Type   | Tunnel name");
		Console.WriteLine("------------------------------------------------------------");
		foreach (TunnelInfo tunnelInfo in tunnels) {
			string tunnelid = "" + tunnelInfo.TunnelId;
			string type = tunnelInfo.Type;
			string name = tunnelInfo.Name;

			for (int i=0; i<(8-tunnelid.Length); i++)
				Console.Write(" ");
			Console.Write(tunnelid);
			Console.Write(" | ");
			Console.Write(type);
			for (int i=0; i<(6-type.Length); i++)
				Console.Write(" ");

			Console.Write(" | ");
			Console.WriteLine(name);
		}
		Console.WriteLine("");
	}

	private static void addTunnel(UserDatabase userDB, Int64 ownerId) {
		string name;

		Console.Write("Tunnel name: ");
		name = Console.ReadLine();

		TunnelInfo tunnelInfo = new TunnelInfo();
		tunnelInfo.OwnerId = ownerId;
		tunnelInfo.Enabled = true;
		tunnelInfo.Name = name;
		tunnelInfo.Type = "tic";
		tunnelInfo.Endpoint = "ayiya";
		tunnelInfo.UserEnabled = true;
		userDB.AddTunnelInfo(tunnelInfo);
	}

	private static void deleteTunnel(UserDatabase userDB, Int64 tunnelId) {
	}
}
