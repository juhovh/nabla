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
using System.Collections.Generic;
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
			public IPAddress RemoteAddress;
			public IPAddress LocalAddress;

			public string UserName;
			public Int64 UserId;
		}

		private SessionManager _sessionManager;
		private ProtocolType _protocolType;
		private UserDatabase _db;
		private SessionInfo _sessionInfo;
		private List<string> _responseQueue;
		private bool _finished = false;

		private SASLAuth _saslAuth = null;

		public TSPSession(SessionManager sessionManager, string dbName, ProtocolType type,
		                  IPAddress remoteAddress, IPAddress localAddress) {
			_sessionManager = sessionManager;
			_db = new UserDatabase(dbName);
			_protocolType = type;
			_sessionInfo = new SessionInfo();
			_sessionInfo.RemoteAddress = remoteAddress;
			_sessionInfo.LocalAddress = localAddress;
			_responseQueue = new List<string>();
		}

		public void Cleanup() {
			_db.Dispose();
		}

		public void QueueResponse(string response) {
			if (_sessionInfo.State == SessionState.Main) {
				int length = Encoding.UTF8.GetBytes(response).Length;
				response = "Content-length: " + length + "\r\n" + response;
			}
			_responseQueue.Add(response);
		}

		public byte[] DequeueResponse() {
			if (_responseQueue.Count == 0) {
				return null;
			}

			string response = _responseQueue[0];
			_responseQueue.RemoveAt(0);
			return Encoding.UTF8.GetBytes(response);
		}

		public void HandleCommand(string command) {
			/* Remove null bytes from beginning and end, Gateway6 client
			 * seems to insert them in the end of strings, that sucks */
			while (command.StartsWith("\0")) {
				command = command.Substring(1);
			}
			while (command.EndsWith("\0")) {
				command = command.Substring(0, command.Length-1);
			}

			/* Trim the last newline from the command as useless */
			if (command.EndsWith("\r\n")) {
				command = command.Substring(0, command.Length-2);
			}

			/* If it's an empty command, simply don't do anything */
			if (command.Trim().Equals("")) {
				return;
			}

			/* If authentication in process, send the command there */
			if (_saslAuth != null && !_saslAuth.Finished) {
				string response = _saslAuth.GetResponse(command);
				if (_saslAuth.Success) {
					if (response != null) {
						QueueResponse(response);
					}
					QueueResponse("200 Success\r\n");

					_sessionInfo.State = SessionState.Main;
				} else if (_saslAuth.Finished) {
					/* Authentication failed, start again */
					_saslAuth = null;
					_sessionInfo.UserName = null;
					_sessionInfo.UserId = 0;
				}
			} else {
				/* Handle all other commands here */
				string response = handleCommand(command);
				if (response != null) {
					QueueResponse(response + "\r\n");
				}
			}
		}

		public bool Finished() {
			return _finished;
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

				if (_sessionManager.IPv4IsAvailable) {
					capability += " TUNNEL=V4V6";
				}
				if (_sessionManager.IPv6IsAvailable) {
					capability += " TUNNEL=V6V4 TUNNEL=V6UDPV4";
				}

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
				} catch (XmlException xmle) {
					/* XXX: Handle parsing errors */
					Console.WriteLine("XML parsing error: " + xmle);
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
						    _sessionInfo.RemoteAddress.AddressFamily) {
							continue;
						}

						/* If addresses don't match, we're behind NAT */
						behindNAT = !_sessionInfo.RemoteAddress.Equals(srcAddr);
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

			if (_sessionInfo.LocalAddress.AddressFamily ==
			    AddressFamily.InterNetworkV6 &&
			    type.Equals("v6udpv4")) {
				return "303 Can't initiate v6udpv4 tunnel over IPv6";
			}

			TunnelInfo tunnel = null;
			TunnelInfo[] tunnels = _db.ListTunnels(_sessionInfo.UserId, "tsp");
			foreach (TunnelInfo t in tunnels) {
				Console.WriteLine("Checking tunnel endpoint: " + t.Endpoint);
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
				clientAddress = _sessionManager.GetIPv6TunnelRemoteAddress(tunnel.TunnelId);
				serverAddress = _sessionManager.GetIPv6TunnelLocalAddress(tunnel.TunnelId);
			} else if (type.Equals("v4v6")) {
				clientAddress = _sessionManager.GetIPv4TunnelRemoteAddress(tunnel.TunnelId);
				serverAddress = _sessionManager.GetIPv4TunnelLocalAddress(tunnel.TunnelId);
			} else {
				return "303 Unknown tunnel type: " + type;
			}

			if (clientAddress == null || serverAddress == null) {
				return "303 Tunnel type " + type + " not configured";
			}

			/* XXX: Set the real keepalive interval and address */
			string lifetime = "604800";
			IPAddress keepaliveAddress = serverAddress;
			int keepaliveInterval = 30;

			XmlDocument response = new XmlDocument();
			XmlElement tunnelNode = response.CreateElement("tunnel");
			XmlElement serverNode = response.CreateElement("server");
			XmlElement clientNode = response.CreateElement("client");
			XmlElement keepaliveNode = response.CreateElement("keepalive");

			keepaliveNode.SetAttribute("interval", keepaliveInterval.ToString());
			keepaliveNode.AppendChild(addressToElement(response, keepaliveAddress));

			clientNode.AppendChild(addressToElement(response, _sessionInfo.RemoteAddress));
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

			return "200 Success\r\n" + response.OuterXml;
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
