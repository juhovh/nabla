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

		private TICDatabase _db;
		private SessionInfo _sessionInfo;
		private bool _finished = false;

		public TSPSession() {
			_db = new TICDatabase("nabla.db");
			_sessionInfo = new SessionInfo();
		}

		public void Cleanup() {
			_db.Cleanup();
		}

		public string HandleCommand(string command) {
			Console.WriteLine("Handling command: " + command);
			return handleCommand(command) + "\r\n";
		}

		public bool Finished() {
			return _finished;
		}

		private string handleCommand(string command) {
			string[] words = command.Split(new char[] {' '},
			                               StringSplitOptions.RemoveEmptyEntries);

			if (_sessionInfo.State == SessionState.Initial) {
				if (!command.Equals("VERSION=2.0.0")) {
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
				_finished = true;
				return "310 Unknown command";
			}
		}
	}
}
