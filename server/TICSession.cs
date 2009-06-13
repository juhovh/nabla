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
			public SessionState State = SessionState.Initial;
			public IPAddress SourceAddress;
			public IPAddress LocalAddress;

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

		private SessionManager _sessionManager;
		private string _serviceName;
		private UserDatabase _db;
		private SessionInfo _sessionInfo;
		private bool _finished = false;

		public TICSession(SessionManager sessionManager, string serviceName,
		                  IPAddress source, IPAddress local) {
			_sessionManager = sessionManager;
			_serviceName = serviceName;

			_db = new UserDatabase("nabla.db");
			_sessionInfo = new SessionInfo();
			_sessionInfo.SourceAddress = source;
			_sessionInfo.LocalAddress = local;
		}

		public void Cleanup() {
			_db.Dispose();
		}

		public string HandleCommand(string command) {
			string[] words = command.Split(new char[] {' '},
			                               StringSplitOptions.RemoveEmptyEntries);
			string response = handleCommand(words) + "\n";
			if (_sessionInfo.PromptEnabled) {
				response += ("config$ ");
			}

			return response;
		}

		public bool Finished() {
			return _finished;
		}

		private string handleCommand(string[] words) {
			if (words.Length == 0) {
				return "200 Empty line, please enter at least something we accept";
			} else if (words[0].Equals("help")) {
				return getHelpString();
			} else if (words[0].Equals("exit")) {
				if (_sessionInfo.State == SessionState.Tunnel ||
				    _sessionInfo.State == SessionState.Route ||
				    _sessionInfo.State == SessionState.Pop) {
					_sessionInfo.State = SessionState.Main;
					return "200 Context set to main";
				}

				/* In other cases exit is equivalent to quit */
				_finished = true;
				return "200 Thank you for using this " + _serviceName + " service";
			} else if (words[0].Equals("quit")) {
				_finished = true;
				return "200 Thank you for using this " + _serviceName + " service";
			} else if (words[0].Equals("starttls") && _sessionInfo.State == SessionState.Initial) {
				return "400 This service is not SSL enabled (yet)";
			} else if (words[0].Equals("client") && _sessionInfo.State == SessionState.Initial) {
				if (words.Length < 2 || !words[1].Contains("/")) {
					return "400 A valid client identifier is expected";
				}

				_sessionInfo.ClientName = words[1].Substring(0, words[1].IndexOf('/'));
				_sessionInfo.ClientVersion = words[1].Substring(words[1].IndexOf('/')+1);

				if (words.Length >= 3 && words[2].Contains("/")) {
					_sessionInfo.OSName = words[2].Substring(0, words[2].IndexOf('/'));
					_sessionInfo.OSVersion = words[2].Substring(words[2].IndexOf('/')+1);
				} else if (words.Length >= 3) {
					_sessionInfo.OSName = words[2];
				}

				return "200 Client Identity accepted";
			} else if (words[0].Equals("username") && _sessionInfo.State == SessionState.Initial) {
				if (words.Length != 2) {
					return "400 A username is expected";
				}

				_sessionInfo.UserName = words[1];
				_sessionInfo.State = SessionState.Challenge;

				return "200 Choose your authentication challenge please";
			} else if (words[0].Equals("challenge") && _sessionInfo.State == SessionState.Challenge) {
				if (words.Length != 2) {
					return "400 Challenge expects a authentication type";
				}

				_sessionInfo.ChallengeType = words[1];
				_sessionInfo.State = SessionState.Authenticate;

				if (words[1].Equals("clear")) {
					return "200 Cleartext authentication has no challenge";
				} else if (words[1].Equals("md5")) {
					MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
					byte[] challBytes = Encoding.ASCII.GetBytes(_sessionInfo.UserName + DateTime.Now);
					byte[] hashBytes = md5.ComputeHash(challBytes);
					string hashStr
						= BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

					_sessionInfo.Challenge = hashStr;
					return "200 " + _sessionInfo.Challenge;
				} else {
					_sessionInfo.State = SessionState.Challenge;
					return "400 Unknown authentication type: " + words[1];
				}
			} else if (words[0].Equals("authenticate") && _sessionInfo.State == SessionState.Authenticate) {
				if (words.Length != 3) {
					return "400 Authenticate requires 2 arguments";
				}

				if (!words[1].Equals(_sessionInfo.ChallengeType)) {
					_sessionInfo.State = SessionState.Challenge;
					return "400 Challenge authentication type differs";
				}

				UserInfo userInfo = _db.GetUserInfo(_sessionInfo.UserName);
				if (userInfo == null) {
					_sessionInfo.State = SessionState.Initial;
					return "400 User " + _sessionInfo.UserName + " does not exist in the DB.";
				}
	
				bool passwordMatch;
				string passwordHash = userInfo.TunnelPassword;
				MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
				if (words[1].Equals("clear")) {
					byte[] pwBytes = Encoding.UTF8.GetBytes(words[2]);
					byte[] theirHash = md5.ComputeHash(pwBytes);
					string theirHashStr
						= BitConverter.ToString(theirHash).Replace("-", "").ToLower();

					passwordMatch = theirHashStr.Equals(passwordHash);
				} else if (words[1].Equals("md5")) {
					byte[] ourBytes = Encoding.ASCII.GetBytes(_sessionInfo.Challenge + passwordHash);
					byte[] ourHash = md5.ComputeHash(ourBytes);
					string ourHashStr
						= BitConverter.ToString(ourHash).Replace("-", "").ToLower();

					string theirHashStr = words[2];
					passwordMatch = theirHashStr.Equals(ourHashStr);
				} else {
					return "400 Unknown authentication type: " + words[1];
				}

				if (!passwordMatch) {
					_sessionInfo.State = SessionState.Initial;
					return "400 Login failed, login/password mismatch";
				}

				_sessionInfo.UserId = userInfo.UserId;
				_sessionInfo.State = SessionState.Main;

				string ret = "200 Succesfully logged in using " + _sessionInfo.ChallengeType;
				ret += " as " + userInfo.UserName + " (" + userInfo.FullName + ")";
				ret += " from " + _sessionInfo.SourceAddress;
				return ret;
			} else if (words[0].Equals("tunnel") && _sessionInfo.State == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handleTunnelCommand(tmp);
				}

				_sessionInfo.State = SessionState.Tunnel;
				return "200 Context set to tunnel";
			} else if (words[0].Equals("route") && _sessionInfo.State == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handleRouteCommand(tmp);
				}

				_sessionInfo.State = SessionState.Route;
				return "200 Context set to route";
			} else if (words[0].Equals("pop") && _sessionInfo.State == SessionState.Main) {
				if (words.Length > 1) {
					/* Execute the command directly in current context */
					string[] tmp = new string[words.Length-1];
					Array.Copy(words, 1, tmp, 0, tmp.Length);
					return handlePopCommand(tmp);
				}

				_sessionInfo.State = SessionState.Pop;
				return "200 Context set to pop";
			} else if (_sessionInfo.State == SessionState.Tunnel) {
				return handleTunnelCommand(words);
			} else if (_sessionInfo.State == SessionState.Route) {
				return handleRouteCommand(words);
			} else if (_sessionInfo.State == SessionState.Pop) {
				return handlePopCommand(words);
			} else if (words[0].Equals("set")) {
				if (words.Length != 3) {
					return "400 'set' requires two arguments";
				}

				if (words[1].Equals("prompt")) {
					if (words[2].Equals("enabled")) {
						_sessionInfo.PromptEnabled = true;
						return "200 Prompt enabled";
					} else if (words[2].Equals("disabled")) {
						_sessionInfo.PromptEnabled = false;
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
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string handleTunnelCommand(string[] words) {
			if (words[0].Equals("list")) {
				TunnelInfo[] tunnels = _db.ListTunnels(_sessionInfo.UserId, "tic");

				string ret = "201 Listing tunnels\n";
				foreach (TunnelInfo t in tunnels) {
					/* Get IPv6 endpoint from SessionManager */
					IPAddress ipv6Endpoint = null, ipv6POP = null;
					if (!_sessionManager.GetTunnelIPv6Endpoints(t.TunnelId, ref ipv6Endpoint, ref ipv6POP)) {
						/* No known endpoints for this tunnel, maybe IPv6 not enabled? */
						continue;
					}

					ret += String.Format("T{0} {1} {2} nabla\n",
						t.TunnelId, ipv6Endpoint, t.Endpoint);
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

				TunnelInfo tunnelInfo = _db.GetTunnelInfo(tunnelId);
				if (tunnelInfo == null) {
					return "400 Unknown tunnel endpoint T" + tunnelId;
				}

				if (tunnelInfo.OwnerId != _sessionInfo.UserId) {
					return "400 T" + tunnelId + " is not one of your tunnels";
				}

				/* Only these values are from the database */
				TICTunnelInfo ticTunnelInfo = new TICTunnelInfo(tunnelInfo.TunnelId);
				ticTunnelInfo.TunnelName = tunnelInfo.Name;
				ticTunnelInfo.IPv4Endpoint = tunnelInfo.Endpoint;
				ticTunnelInfo.UserEnabled = tunnelInfo.UserEnabled;
				ticTunnelInfo.AdminEnabled = tunnelInfo.Enabled;
				ticTunnelInfo.Password = tunnelInfo.Password;

				/* Get IPv6Endpoint and IPv6POP from SessionManager */
				IPAddress ipv6Endpoint = null, ipv6POP = null;
				if (!_sessionManager.GetTunnelIPv6Endpoints(tunnelId, ref ipv6Endpoint, ref ipv6POP)) {
					/* No known endpoints for this tunnel, maybe IPv6 not enabled? */
					return "400 Error in tunnel T" + tunnelId + " configuration";
				}
				ticTunnelInfo.IPv6Endpoint = ipv6Endpoint;
				ticTunnelInfo.IPv6POP = ipv6POP;

				/* Some constants that don't need to change */
				ticTunnelInfo.IPv6PrefixLength = 64;
				ticTunnelInfo.TunnelMTU = 1280;
				ticTunnelInfo.POPId = "nabla";
				ticTunnelInfo.IPv4POP = _sessionInfo.LocalAddress;
				ticTunnelInfo.HeartbeatInterval = 3600;

				string ret = "201 Showing tunnel information for T" + tunnelId + "\n";
				ret += ticTunnelInfo.ToString();
				ret += "202 Done";

				return ret;
			} else if (words[0].Equals("set")) {
				if (words.Length != 4) {
					return "400 set requires 3 arguments";
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

				TunnelInfo tunnelInfo = _db.GetTunnelInfo(tunnelId);
				if (tunnelInfo == null) {
					return "400 Unknown tunnel endpoint T" + tunnelId;
				}

				if (words[2].Equals("endpoint")) {
					if (!words[3].Equals("heartbeat") && !words[3].Equals("ayiya")) {
						bool valid = false;
						try {
							IPAddress addr = IPAddress.Parse(words[3]);
							if (addr.AddressFamily == AddressFamily.InterNetwork) {
								byte[] b = addr.GetAddressBytes();
								if (b[0] == 10 ||
								    (b[0] == 172 && (b[1]&0xf0) == 0x10) ||
								    (b[0] == 192 && b[1] == 168)) {
									return "400 RFC1918 Address";
								} else {
									valid = true;
								}
							}
						} catch (Exception) {}

						if (!valid) {
							return "400 invalid IPv4 address";
						}
					}

					_db.UpdateTunnelEndpoint(tunnelId, words[3]);
					return "200 Endpoint of T" + tunnelId + " changed to " + words[3];
				} else if (words[2].Equals("state")) {
					bool enabled;

					if (words[3].Equals("enabled")) {
						enabled = true;
					} else if (words[3].Equals("disabled")) {
						enabled = false;
					} else {
						return "400 Defined state " + words[3] + " unknown";
					}

					if (tunnelInfo.UserEnabled == enabled) {
						return "400 Tunnel was already in the requested state";
					}

					_db.UpdateTunnelUserEnabled(tunnelId, enabled);
					return "State of T" + tunnelId + " changed to " + words[3];
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

		private string handleRouteCommand(string[] words) {
			if (words[0].Equals("list")) {
				RouteInfo[] routes = _db.ListRoutes(_sessionInfo.UserId);

				string ret = "201 Listing routes\n";
				foreach (RouteInfo r in routes) {
					/* XXX: IPv6Prefix and IPv6PrefixLength SessionManager */
					IPAddress ipv6Prefix = IPAddress.Parse("2001::1");
					int ipv6PrefixLength = 64;

					ret += String.Format("R{0} T{1} {2}/{3}\n",
						r.RouteId, r.TunnelId, ipv6Prefix, ipv6PrefixLength);
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

				RouteInfo routeInfo = _db.GetRouteInfo(routeId);
				if (routeInfo == null) {
					return "400 Unknown route R" + routeId;
				}

				if (routeInfo.OwnerId != _sessionInfo.UserId) {
					return "400 T" + routeId + " is not your route";
				}

				/* Only these values are from the database */
				TICRouteInfo ticRouteInfo = new TICRouteInfo(routeInfo.RouteId);
				ticRouteInfo.Description = routeInfo.Description;
				ticRouteInfo.Created = routeInfo.Created;
				ticRouteInfo.LastModified = routeInfo.LastModified;
				ticRouteInfo.UserEnabled = routeInfo.UserEnabled;
				ticRouteInfo.AdminEnabled = routeInfo.Enabled;

				/* XXX: IPv6Prefix and IPv6PrefixLength from SessionManager */
				ticRouteInfo.IPv6Prefix = IPAddress.Parse("2001::1");
				ticRouteInfo.IPv6PrefixLength = 64;

				string ret = "201 Showing route information for R" + routeId + "\n";
				ret += ticRouteInfo.ToString();
				ret += "202 Done";

				return ret;
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string handlePopCommand(string[] words) {
			if (words[0].Equals("list")) {
				string ret = "201 Listing PoPs\n";
				ret += "nabla\n";
				ret += "202 <pop_name>";
				return ret;
			} else if (words[0].Equals("show")) {
				if (words.Length != 2) {
					return "400 Show requires a pop id";
				}

				if (!words[1].Equals("nabla")) {
					return "400 Unknown PoP '" + words[1] + "'";
				}

				TICPopInfo popInfo = new TICPopInfo(words[1]);
				popInfo.City = "Unknown";
				popInfo.Country = "Unknown";
				popInfo.IPv4 = IPAddress.Parse("127.0.0.1");
				popInfo.IPv6 = IPAddress.Parse("::");
				popInfo.HeartbeatSupport = "Y";
				popInfo.TincSupport = "N";
				popInfo.MulticastSupport = "N";
				popInfo.ISPShort = "Nabla";
				popInfo.ISPName = "Nabla - Automatic IPv6 Tunneling and Connectivity";
				popInfo.ISPWebsite = "http://code.google.com/p/nabla/";
				popInfo.ISPASNumber = 0;
				popInfo.ISPLIRId = "nabla";

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

			switch (_sessionInfo.State) {
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
