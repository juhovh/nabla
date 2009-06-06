using System;
using Nabla.Database;

public class TICDatabaseCreate {
	private static void Main(string[] args) {
		if (args.Length != 1) {
			Console.WriteLine("Requires database filename argument");
			return;
		}

		TICDatabase db = new TICDatabase(args[0]);
		db.CreateTables();

		TICUserInfo info = new TICUserInfo();
		info.UserName = "juhovh";
		info.Password = "testi";
		info.FullName = "Juho Vähä-Herttua";
		db.AddUserInfo(info);
	}
}

