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
using System.Xml;
using System.Text;
using System.Security.Cryptography;
using Nabla.Database;

namespace Nabla {
	public class TSPSession {
		private enum SessionState {
			Initial,
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

			public string UserName;
			public Int64 UserId;
		}

		private SessionManager _sessionManager;
		private ProtocolType _protocolType;
		private UserDatabase _db;
		private SessionInfo _sessionInfo;
		private bool _finished = false;

		private SASLAuth _saslAuth = null;

		public TSPSession(SessionManager sessionManager, string dbName, ProtocolType type,
		                  IPAddress sourceAddress, IPAddress localAddress) {
			_sessionManager = sessionManager;
			_db = new UserDatabase(dbName);
			_protocolType = type;
			_sessionInfo = new SessionInfo();
			_sessionInfo.SourceAddress = sourceAddress;
			_sessionInfo.LocalAddress = localAddress;
		}

		public void Cleanup() {
			_db.Dispose();
		}

		public string[] HandleCommand(string command) {
			Console.WriteLine("Handling command: " + command);

			string response;
			if (_saslAuth != null && !_saslAuth.Finished) {
				response = _saslAuth.GetResponse(command);
				if (_saslAuth.Success) {
					_sessionInfo.State = SessionState.Main;

					if (response == null) {
						response = "200 Authentication successful";
					} else {
						/* We need to reply in two separate packets, very stupid */
						return new string[] { response, "200 Success\r\n" };
					}
				}
			} else {
				_saslAuth = null;
				response = handleCommand(command);
			}

			if (response == null) {
				return null;
			}

			Console.WriteLine("Outputting response: " + response);
			return new string[] { response + "\r\n" };
		}

		public bool Finished() {
			return _finished;
		}

		public bool OutputContentLength {
			get {
				return (_sessionInfo.State == SessionState.Main);
			}
		}

		private string handleCommand(string command) {
			string[] words = command.Split(new char[] {' '},
			                               StringSplitOptions.RemoveEmptyEntries);

			if (_sessionInfo.State == SessionState.Initial) {
				if (!command.StartsWith("VERSION=2.0")) {
					_finished = true;
					return "302 Unsupported client version";
				}

				_sessionInfo.State = SessionState.Authenticate;

				/* XXX: Should return the real tunnel capabilities */
				string capability = "CAPABILITY";
				capability += " TUNNEL=V6V4 TUNNEL=V6UDPV4";
				string[] authMethods = SASLAuth.GetSupportedMethods();
				foreach (string m in authMethods) {
					capability += " AUTH=" + m;
				}

				return capability;
			} else if (_sessionInfo.State == SessionState.Authenticate) {
				if (!words[0].Equals("AUTHENTICATE")) {
					return "300 Authentication failed";
				}

				SASLAuthCallback callback = new SASLAuthCallback(getPassword);
				_saslAuth = new SASLAuth(words[1], "nabla", callback);
				return _saslAuth.GetChallenge();
			} else {
				XmlDocument xmlDoc = new XmlDocument();
				try {
					xmlDoc.LoadXml(command);
				} catch (XmlException) {
					/* XXX: Handle parsing errors */
				}
				return handleXmlCommand(xmlDoc);
			}
		}

		private string handleXmlCommand(XmlDocument xmlDoc) {
			XmlElement doc = xmlDoc.DocumentElement;
			if (!doc.Name.Equals("tunnel")) {
				/* XXX: Handle unknown element */
			}

			if (!doc.HasAttribute("action")) {
				/* XXX: Handle missing required attribute */
			}

			string action = doc.GetAttribute("action");
			string type = doc.GetAttribute("type");

			Console.WriteLine("Tunnel request action: " + action + " type: " + type);

			if (action.Equals("create")) {
				return handleCreateCommand(doc, type);
			} else if (action.Equals("delete")) {
				return handleDeleteCommand(doc, type);
			} else if (action.Equals("info")) {
				return handleInfoCommand(doc, type);
			} else if (action.Equals("accept")) {
				return handleAcceptCommand(doc, type);
			} else if (action.Equals("reject")) {
				return handleRejectCommand(doc, type);
			} else {
				/* XXX: Handle invalid action */
				return "310 Unknown command";
			}
		}

		private string handleCreateCommand(XmlElement doc, string type) {
			bool behindNAT = true;

			foreach (XmlElement c in doc.ChildNodes) {
				if (!c.Name.Equals("client"))
					continue;

				foreach (XmlElement cc in c.ChildNodes) {
					if (cc.Name.Equals("address")) {
						IPAddress srcAddr = elementToAddress(cc);
						if (srcAddr == null) {
							/* XXX: Handle invalid address */
							continue;
						}

						if (srcAddr.AddressFamily !=
						    _sessionInfo.SourceAddress.AddressFamily) {
							continue;
						}

						/* If addresses don't match, we're behind NAT */
						behindNAT = !_sessionInfo.SourceAddress.Equals(srcAddr);
					}
				}
			}

			if (behindNAT) {
				if (type.Equals("v6anyv4")) {
					type = "v6udpv4";
				}

				if (_protocolType != ProtocolType.Udp) {
					return "303 Can't initiate NAT connection over TCP";
				} else if (!type.Equals("v6udpv4")) {
					return "303 Can't initiate non-UDP tunnel with NAT";
				}
			} else {
				if (type.Equals("v6anyv4")) {
					type = "v6v4";
				}
			}

			TunnelInfo tunnel = null;
			TunnelInfo[] tunnels = _db.ListTunnels(_sessionInfo.UserId, "tsp");
			foreach (TunnelInfo t in tunnels) {
				if (!t.Enabled || !t.UserEnabled)
					continue;

				if ((type.Equals("v6v4") || type.Equals("v6udpv4")) &&
				    t.Endpoint.Equals("ipv4")) {
					tunnel = t;
					break;
				} else if (type.Equals("v4v6") && t.Endpoint.Equals("ipv6")) {
					tunnel = t;
					break;
				}
			}

			if (tunnel == null) {
				return "303 No suitable tunnel for type " + type + " found";
			}

			IPAddress clientAddress, serverAddress;
			if (type.Equals("v6v4") || type.Equals("v6udpv4")) {
				clientAddress = _sessionManager.GetIPv6TunnelEndpoint(tunnel.TunnelId);
				serverAddress = _sessionManager.GetIPv6ServerEndpoint();
			} else if (type.Equals("v4v6")) {
				clientAddress = _sessionManager.GetIPv4TunnelEndpoint(tunnel.TunnelId);
				serverAddress = _sessionManager.GetIPv4ServerEndpoint();
			} else {
				return "303 Unknown tunnel type: " + type;
			}

			if (clientAddress == null || serverAddress == null) {
				return "303 Tunnel type " + type + " not configured";
			}

			/* XXX: Set the real keepalive interval and address */
			string lifetime = "1440";
			IPAddress keepaliveAddress = serverAddress;
			int keepaliveInterval = 30;

			XmlDocument response = new XmlDocument();
			XmlElement tunnelNode = response.CreateElement("tunnel");
			XmlElement serverNode = response.CreateElement("server");
			XmlElement clientNode = response.CreateElement("client");
			XmlElement keepaliveNode = response.CreateElement("keepalive");

			keepaliveNode.SetAttribute("interval", keepaliveInterval.ToString());
			keepaliveNode.AppendChild(addressToElement(response, keepaliveAddress));

			clientNode.AppendChild(addressToElement(response, _sessionInfo.SourceAddress));
			clientNode.AppendChild(addressToElement(response, clientAddress));
			clientNode.AppendChild(keepaliveNode);

			serverNode.AppendChild(addressToElement(response, _sessionInfo.LocalAddress));
			serverNode.AppendChild(addressToElement(response, serverAddress));

			tunnelNode.SetAttribute("action", "info");
			tunnelNode.SetAttribute("type", type);
			tunnelNode.SetAttribute("lifetime", lifetime);
			tunnelNode.AppendChild(serverNode);
			tunnelNode.AppendChild(clientNode);

			response.AppendChild(tunnelNode);

			return "200 OK\r\n" + response.OuterXml;
		}

		private string handleDeleteCommand(XmlElement doc, string type) {
			/* XXX: Handle invalid action */
			return "310 Unknown command";
		}

		private string handleInfoCommand(XmlElement doc, string type) {
			/* XXX: Handle invalid action */
			return "310 Unknown command";
		}

		private string handleAcceptCommand(XmlElement doc, string type) {
			return null;
		}

		private string handleRejectCommand(XmlElement doc, string type) {
			return null;
		}

		private string getPassword(string username) {
			UserInfo userInfo = _db.GetUserInfo(username);
			if (userInfo == null) {
				return null;
			}

			_sessionInfo.UserName = userInfo.UserName;
			_sessionInfo.UserId = userInfo.UserId;

			return userInfo.TunnelPassword;
		}

		private IPAddress elementToAddress(XmlElement element) {
			if (element.Name.Equals("address")) {
				try {
					IPAddress address = IPAddress.Parse(element.FirstChild.Value);
					string type = getAddressType(address);
					if (type.Equals(element.GetAttribute("type"))) {
						return address;
					}
				} catch (Exception) {}
			}

			return null;
		}

		private XmlElement addressToElement(XmlDocument doc, IPAddress address) {
			XmlElement element = doc.CreateElement("address");
			element.SetAttribute("type", getAddressType(address));
			element.AppendChild(doc.CreateTextNode(address.ToString()));
			return element;
		}

		private string getAddressType(IPAddress address) {
			switch (address.AddressFamily) {
			case AddressFamily.InterNetwork:
				return "ipv4";
			case AddressFamily.InterNetworkV6:
				return "ipv6";
			default:
				return null;
			}
		}
	}
}
