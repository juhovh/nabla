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

		private ProtocolType _protocolType;
		private UserDatabase _db;
		private SessionInfo _sessionInfo;
		private bool _finished = false;

		public TSPSession(ProtocolType type, IPAddress sourceAddress, IPAddress localAddress) {
			_protocolType = type;
			_db = new UserDatabase("nabla.db");
			_sessionInfo = new SessionInfo();
			_sessionInfo.SourceAddress = sourceAddress;
			_sessionInfo.LocalAddress = localAddress;
		}

		public void Cleanup() {
			_db.Dispose();
		}

		public string HandleCommand(string command) {
			Console.WriteLine("Handling command: " + command);

			string response = handleCommand(command);
			if (response == null) {
				return null;
			}

			return response + "\r\n";
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

				/* XXX: Should return the real capabilities */
				_sessionInfo.State = SessionState.Authenticate;
				return "CAPABILITY TUNNEL=V6V4 TUNNEL=V6UDPV4 AUTH=ANONYMOUS";
			} else if (_sessionInfo.State == SessionState.Authenticate) {
				if (!words[0].Equals("AUTHENTICATE")) {
					return "300 Authentication failed";
				}

				_sessionInfo.State = SessionState.Main;
				return "200 Success";
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
					/* XXX: Type needs to be UDP */
				} else if (!type.Equals("v6udpv4")) {
					/* XXX: No suitable tunnel found */
				}
			} else {
				if (type.Equals("v6anyv4")) {
					type = "v6v4";
				}
			}

			/* XXX: Check that type is correct and call SessionManager */
			/* XXX: Set the real keepalive interval and address */
			string lifetime = "1440";
			IPAddress clientAddress = IPAddress.Parse("2001::1");
			IPAddress serverAddress = IPAddress.Parse("2001::1");
			IPAddress keepaliveAddress = serverAddress;
			int keepaliveInterval = 30;

			XmlDocument response = new XmlDocument();
			XmlElement tunnel = response.CreateElement("tunnel");
			XmlElement server = response.CreateElement("server");
			XmlElement client = response.CreateElement("client");
			XmlElement keepalive = response.CreateElement("keepalive");

			keepalive.SetAttribute("interval", keepaliveInterval.ToString());
			keepalive.AppendChild(addressToElement(response, keepaliveAddress));

			client.AppendChild(addressToElement(response, _sessionInfo.SourceAddress));
			client.AppendChild(addressToElement(response, clientAddress));
			client.AppendChild(keepalive);

			server.AppendChild(addressToElement(response, _sessionInfo.LocalAddress));
			server.AppendChild(addressToElement(response, serverAddress));

			tunnel.SetAttribute("action", "info");
			tunnel.SetAttribute("type", type);
			tunnel.SetAttribute("lifetime", lifetime);
			tunnel.AppendChild(server);
			tunnel.AppendChild(client);

			response.AppendChild(tunnel);

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