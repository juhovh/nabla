/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009  Juho Vähä-Herttua
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using Nabla.Database;

namespace Nabla {
	public class TICSession {
		private enum SessionState {
			Initial,
			Challenge,
			Authenticate,
			Main,

			Tunnel,
			Route,
			Pop
		};

		private class SessionInfo {
			public bool PromptEnabled;
			public string ClientName;
			public string ClientVersion;
			public string OSName;
			public string OSVersion;

			public string UserName;
			public string ChallengeType;
			public string Challenge;

			public Int64 UserId;
		}

		private TcpClient _client;
		private StreamReader _reader;
		private StreamWriter _writer;

		private string _serviceName;
		private string _serviceUrl;

		private Object _runlock = new Object();
		private volatile bool _running = false;

		private Thread _thread;

		private SessionState _state = SessionState.Initial;

		public TICSession(TcpClient client, string serviceName, string serviceUrl) {
			_client = client;
			_reader = new StreamReader(client.GetStream());
			_writer = new StreamWriter(client.GetStream());

			_serviceName = serviceName;
			_serviceUrl = serviceUrl;

			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start() {
			lock (_runlock) {
				_running = true;
				_thread.Start();
			}
			
		}

		public void Stop() {
			lock (_runlock) {
				_running = false;
				_thread.Join();
			}
		}

		private void threadLoop() {
			TICDatabase db = new TICDatabase("nabla.db");
			SessionInfo info = new SessionInfo();

			/* Write the initial welcome line */
			_writer.WriteLine("200 " + _serviceName + " TIC Service on " + Dns.GetHostName() + " ready (" + _serviceUrl + ")");
			_writer.Flush();

			while (_running) {
				if (info.PromptEnabled) {
					_writer.Write("config$ \n");
				}

				string line = _reader.ReadLine().Trim();
				string[] words = line.Split(new char[] {' '},
				                            StringSplitOptions.RemoveEmptyEntries);

				string response = handleCommand(db, info, words);
				_writer.Write(response + "\n");
				_writer.Flush();
			}

			_client.Close();
		}

		private string handleCommand(TICDatabase db, SessionInfo info, string[] words) {
			if (words.Length == 0) {
				return "200 Empty line, please enter at least something we accept";
			} else if (words[0].Equals("set")) {
				if (words.Length != 3) {
					return "400 'set' requires two arguments";
				}

				if (words[1].Equals("prompt")) {
					if (words[2].Equals("enabled")) {
						info.PromptEnabled = true;
						return "200 Prompt enabled";
					} else if (words[2].Equals("disabled")) {
						info.PromptEnabled = false;
						return "200 Prompt disabled";
					} else {
						return "400 Can only be enabled or disabled";
					}
				} else {
					return "400 No such option '" + words[1] + "' to set";
				}
			} else if (words[0].Equals("get")) {
				if (words.Length != 2) {
					return "400 'get' requires one argument";
				}

				if (words[1].Equals("unixtime")) {
					UInt32 time = (UInt32) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
					return "200 " + time;
				} else {
					return "400 No such option '" + words[1] + "' to get";
				}
			} else if (words[0].Equals("help")) {
				return getHelpString();
			} else if (words[0].Equals("exit")) {
				if (_state == SessionState.Tunnel ||
				    _state == SessionState.Route ||
				    _state == SessionState.Pop) {
					_state = SessionState.Main;
					return "200 Context set to main";
				}

				/* In other cases exit is equivalent to quit */
				_running = false;
				return "200 Thank you for using this " + _serviceName + " service";
			} else if (words[0].Equals("quit")) {
				_running = false;
				return "200 Thank you for using this " + _serviceName + " service";
			} else if (words[0].Equals("starttls") && _state == SessionState.Initial) {
				return "400 This service is not SSL enabled (yet)";
			} else if (words[0].Equals("client") && _state == SessionState.Initial) {
				if (words.Length < 2 || !words[1].Contains("/")) {
					return "400 A valid client identifier is expected";
				}

				info.ClientName = words[1].Substring(0, words[1].IndexOf('/'));
				info.ClientVersion = words[1].Substring(words[1].IndexOf('/')+1);

				if (words.Length >= 3 && words[2].Contains("/")) {
					info.OSName = words[2].Substring(0, words[2].IndexOf('/'));
					info.OSVersion = words[2].Substring(words[2].IndexOf('/')+1);
				} else if (words.Length >= 3) {
					info.OSName = words[2];
				}

				return "200 Client Identity accepted";
			} else if (words[0].Equals("username") && _state == SessionState.Initial) {
				if (words.Length != 2) {
					return "400 A username is expected";
				}

				info.UserName = words[1];
				_state = SessionState.Challenge;

				return "200 Choose your authentication challenge please";
			} else if (words[0].Equals("challenge") && _state == SessionState.Challenge) {
				if (words.Length != 2) {
					return "400 Challenge expects a authentication type";
				}

				info.ChallengeType = words[1];
				_state = SessionState.Authenticate;

				if (words[1].Equals("clear")) {
					return "200 Cleartext authentication has no challenge";
				} else if (words[1].Equals("md5")) {
					MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
					byte[] challBytes = Encoding.ASCII.GetBytes(info.UserName + DateTime.Now);
					byte[] hashBytes = md5.ComputeHash(challBytes);
					string hashStr
						= BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

					info.Challenge = hashStr;
					return "200 " + info.Challenge;
				} else {
					_state = SessionState.Challenge;
					return "400 Unknown authentication type: " + words[1];
				}
			} else if (words[0].Equals("authenticate") && _state == SessionState.Authenticate) {
				if (words.Length != 3) {
					return "400 Authenticate requires 2 arguments";
				}

				if (!words[1].Equals(info.ChallengeType)) {
					_state = SessionState.Challenge;
					return "400 Challenge authentication type differs";
				}

				TICUserInfo userInfo = db.GetUserInfo(info.UserName);
				if (userInfo == null) {
					_state = SessionState.Initial;
					return "400 User " + info.UserName + " does not exist in the DB.";
				}
	
				bool passwordMatch;
				string passwordHash = userInfo.Password;
				MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
				if (words[1].Equals("clear")) {
					byte[] pwBytes = _reader.CurrentEncoding.GetBytes(words[2]);
					byte[] theirHash = md5.ComputeHash(pwBytes);
					string theirHashStr
						= BitConverter.ToString(theirHash).Replace("-", "").ToLower();

					passwordMatch = theirHashStr.Equals(passwordHash);
				} else if (words[1].Equals("md5")) {
					byte[] ourBytes = Encoding.ASCII.GetBytes(info.Challenge + passwordHash);
					byte[] ourHash = md5.ComputeHash(ourBytes);
					string ourHashStr
						= BitConverter.ToString(ourHash).Replace("-", "").ToLower();

					string theirHashStr = words[2];
					passwordMatch = theirHashStr.Equals(ourHashStr);
				} else {
					return "400 Unknown authentication type: " + words[1];
				}

				if (!passwordMatch) {
					_state = SessionState.Initial;
					return "400 Login failed, login/password mismatch";
				}

				info.UserId = userInfo.UserId;
				_state = SessionState.Main;

				IPEndPoint endPoint = (IPEndPoint) _client.Client.RemoteEndPoint;
				string ret = "200 Succesfully logged in using " + info.ChallengeType;
				ret += " as " + userInfo.UserName + " (" + userInfo.FullName + ")";
				ret += " from " + endPoint.Address;
				return ret;
			} else if (words[0].Equals("tunnel") && _state == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handleTunnelCommand(db, info, tmp);
				}

				_state = SessionState.Tunnel;
				return "200 Context set to tunnel";
			} else if (words[0].Equals("route") && _state == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handleRouteCommand(db, info, tmp);
				}

				_state = SessionState.Route;
				return "200 Context set to route";
			} else if (words[0].Equals("pop") && _state == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handlePopCommand(db, info, tmp);
				}

				_state = SessionState.Pop;
				return "200 Context set to pop";
			} else if (_state == SessionState.Tunnel) {
				return handleTunnelCommand(db, info, words);
			} else if (_state == SessionState.Route) {
				return handleRouteCommand(db, info, words);
			} else if (_state == SessionState.Pop) {
				return handlePopCommand(db, info, words);
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string handleTunnelCommand(TICDatabase db, SessionInfo info, string[] words) {
			if (words[0].Equals("list")) {
				TICTunnelInfo[] tunnels = db.ListTunnels(info.UserId);

				string ret = "201 Listing tunnels\n";
				foreach (TICTunnelInfo t in tunnels) {
					ret += String.Format("T{0} {1} {2} {3}\n",
						t.TunnelId, t.IPv6Endpoint, t.IPv4Endpoint, t.POPId);
				}
				ret += "202 <tunnel_id> <ipv6_endpoint> <ipv4_endpoint> <pop_name>";
				return ret;
			} else if (words[0].Equals("show")) {
				if (words.Length != 2) {
					return "400 Show requires a tunnel id";
				}

				int tunnelId = 0;
				try {
					if (words[1].StartsWith("T")) {
						tunnelId = int.Parse(words[1].Substring(1));
					} else {
						tunnelId = int.Parse(words[1]);
					}
				} catch (Exception) {
					return "400 Given tunnel id '" + words[1] + "' is not valid";
				}

				TICTunnelInfo tunnelInfo = db.GetTunnelInfo(tunnelId);
				if (tunnelInfo == null) {
					return "400 Unknown tunnel endpoint T" + tunnelId;
				}

				if (tunnelInfo.OwnerId != info.UserId) {
					return "400 T" + tunnelId + " is not one of your tunnels";
				}

				string ret = "201 Showing tunnel information for T" + tunnelId + "\n";
				ret += tunnelInfo.ToString();
				ret += "202 Done";

				return ret;
			} else if (words[0].Equals("set")) {
				if (words.Length != 4) {
					return "400 set requires 3 arguments";
				}

				if (words[2].Equals("endpoint")) {
					return "400 Not implemented yet";
				} else if (words[2].Equals("state")) {
					return "400 Not implemented yet";
				} else {
					return "400 " + words[2] + " is not a known variable";
				}
			} else if (words[0].Equals("put")) {
				if (words.Length != 3) {
					return "400 put requires 2 arguments";
				}

				if (words[2].Equals("publickey")) {
					return "400 Not implemented yet";
				} else {
					return "400 " + words[2] + " is not a known variable";
				}
			} else if (words[0].Equals("get")) {
				if (words.Length != 3) {
					return "400 get requires 2 arguments";
				}

				if (words[2].Equals("publickey")) {
					return "400 Not implemented yet";
				} else {
					return "400 " + words[2] + " is not a known variable";
				}
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string handleRouteCommand(TICDatabase db, SessionInfo info, string[] words) {
			if (words[0].Equals("list")) {
				TICRouteInfo[] routes = db.ListRoutes(info.UserId);

				string ret = "201 Listing routes\n";
				foreach (TICRouteInfo r in routes) {
					ret += String.Format("R{0} T{1} {2}/{3}\n",
						r.RouteId, r.TunnelId, r.IPv6Prefix, r.IPv6PrefixLength);
				}
				ret += "202 <route_id> <tunnel_id> <route_prefix>";
				return ret;
			} else if (words[0].Equals("show")) {
				if (words.Length != 2) {
					return "400 Show requires a route id";
				}

				int routeId = 0;
				try {
					if (words[1].StartsWith("R")) {
						routeId = int.Parse(words[1].Substring(1));
					} else {
						routeId = int.Parse(words[1]);
					}
				} catch (Exception) {
					return "400 Given route id '" + words[1] + "' is not valid";
				}

				TICRouteInfo routeInfo = db.GetRouteInfo(routeId);
				if (routeInfo == null) {
					return "400 Unknown route R" + routeId;
				}

				/* XXX: Check that the owner is correct */
				if (routeInfo.OwnerId != info.UserId) {
					return "400 T" + routeId + " is not your route";
				}

				string ret = "201 Showing route information for R" + routeId + "\n";
				ret += routeInfo.ToString();
				ret += "202 Done";

				return ret;
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string handlePopCommand(TICDatabase db, SessionInfo info, string[] words) {
			if (words[0].Equals("list")) {
				TICPopInfo[] pops = db.ListPops();

				string ret = "201 Listing PoPs\n";
				foreach (TICPopInfo p in pops) {
					ret += p.POPId + "\n";
				}
				ret += "202 <pop_name>";
				return ret;
			} else if (words[0].Equals("show")) {
				if (words.Length != 2) {
					return "400 Show requires a pop id";
				}

				TICPopInfo popInfo = db.GetPopInfo(words[1]);
				if (popInfo == null) {
					return "400 Unknown PoP '" + words[1] + "'";
				}

				string ret = "201 Showing PoP information for " + words[1] + "\n";
				ret += popInfo.ToString();
				ret += "202 Done";

				return ret;
			} else if (words[0].Equals("get")) {
				if (words.Length != 3) {
					return "400 get requires 2 arguments";
				}

				if (words[2].Equals("publickey")) {
					return "400 Not implemented yet";
				} else {
					return "400 " + words[2] + " is not a known variable";
				}
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string getHelpString() {
			string ret = "201 Available commands\n";

			string mainCommands = "";
			mainCommands += "set prompt enabled|disabled\n";
			mainCommands += "get unixtime\n";

			switch (_state) {
			case SessionState.Initial:
				ret += "starttls\n";
				ret += "client <name/version> <osname/osversion>\n";
				ret += "username <nic-hdl>\n";
				ret += mainCommands;
				break;
			case SessionState.Challenge:
				ret += "challenge clear|md5\n";
				ret += mainCommands;
				break;
			case SessionState.Authenticate:
				ret += "authenticate clear|md5 <response>\n";
				ret += mainCommands;
				break;
			case SessionState.Main:
				ret += "tunnel\n";
				ret += "route\n";
				ret += "pop\n";
				ret += mainCommands;
				break;
			case SessionState.Tunnel:
				ret += "list\n";
				ret += "show <tunnel-id>\n";
				ret += "set <tunnel-id> endpoint {<new-ipv4>|heartbeat|ayiya}\n";
				ret += "set <tunnel-id> state {enabled|disabled}\n";
				ret += "put <tunnel-id> publickey\n";
				ret += "get <tunnel-id> publickey\n";
				break;
			case SessionState.Route:
				ret += "list\n";
				ret += "show <route-id>\n";
				break;
			case SessionState.Pop:
				ret += "list\n";
				ret += "show <popname>\n";
				ret += "get <popname> publickey\n";
				break;
			}

			ret += "help\n";
			ret += "exit\n";
			ret += "quit\n";

			ret += "202 End of help";

			return ret;
		}
	}
}
