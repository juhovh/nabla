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
using System.Text;
using System.Threading;
using System.Security.Cryptography;

namespace Nabla {
	public class TICSession {
		private enum SessionState {
			Initial,
			Challenge,
			Authenticate,
			Logged
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
		}

		private TextReader _reader;
		private TextWriter _writer;

		private string _serviceName;

		private Object _runlock = new Object();
		private volatile bool _running = false;

		private Thread _thread;

		private SessionState _state = SessionState.Initial;

		public TICSession(TextReader reader, TextWriter writer) {
			_reader = reader;
			_writer = writer;

			_thread = new Thread(new ThreadStart(threadLoop));
		}

		public void Start(string serviceName, string serviceHost, string serviceUrl) {
			lock (_runlock) {
				if (_running) {
					return;
				}

				/* Write the initial welcome line */
				_writer.WriteLine("200 " + serviceName + " TIC Service on " + serviceHost + " ready (" + serviceUrl + ")");
				_writer.Flush();

				_serviceName = serviceName;

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
			SessionInfo info = new SessionInfo();

			while (_running) {
				if (info.PromptEnabled) {
					_writer.Write("config$ \n");
				}

				string line = _reader.ReadLine().Trim();
				string[] words = line.Split(new char[] {' '},
				                            StringSplitOptions.RemoveEmptyEntries);

				string response = handleCommand(info, words);
				_writer.Write(response + "\n");
			}
		}

		private string handleCommand(SessionInfo info, string[] words) {
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
			} else if (words[0].Equals("exit") || words[0].Equals("quit")) {
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

				/* XXX: Save the challenge type */
				info.ChallengeType = words[1];
				_state = SessionState.Authenticate;

				if (words[1].Equals("clear")) {
					return "200 Cleartext authentication has no challenge";
				} else if (words[1].Equals("md5")) {
					/* XXX: Get a real challenge instead */
					info.Challenge = "foobar";
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
					return "400 Challenge authentication type differs";
				}

				/* XXX: Check against the real user name pw in the db */
				string passwordHash = "foobar";
				if (passwordHash == null) {
					_state = SessionState.Initial;
					return "400 User " + info.UserName + " does not exist in the DB.";
				}
	
				bool passwordMatch;
				MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
				if (words[1].Equals("clear")) {
					byte[] pwBytes = Encoding.UTF8.GetBytes(words[2]);
					byte[] theirHash = md5.ComputeHash(pwBytes);
					string theirHashStr
						= BitConverter.ToString(theirHash).Replace("-", "").ToLower();

					passwordMatch = theirHashStr.Equals(passwordHash);
				} else if (words[1].Equals("md5")) {
					byte[] ourBytes = Encoding.UTF8.GetBytes(passwordHash + info.Challenge);
					byte[] ourHash = md5.ComputeHash(ourBytes);
					string ourHashStr
						= BitConverter.ToString(ourHash).Replace("-", "").ToLower();

					byte[] pwBytes = Encoding.UTF8.GetBytes(words[2]);
					byte[] pwHashBytes = md5.ComputeHash(pwBytes);
					byte[] challBytes = Encoding.UTF8.GetBytes(info.Challenge);

					byte[] theirBytes = new byte[pwHashBytes.Length + challBytes.Length];
					Array.Copy(theirBytes, 0, pwBytes, 0, pwBytes.Length);
					Array.Copy(theirBytes, pwBytes.Length, challBytes, 0, challBytes.Length);
					byte[] theirHash = md5.ComputeHash(theirBytes);
					string theirHashStr
						= BitConverter.ToString(theirHash).Replace("-", "").ToLower();

					passwordMatch = theirHashStr.Equals(ourHashStr);
				} else {
					return "400 Unknown authentication type: " + words[1];
				}

				if (!passwordMatch) {
					_state = SessionState.Initial;
					return "400 Login failed, login/password mismatch";
				}

				/* XXX: This should be gotten from the database or elsewhere */
				string fullName = "Foo Bar";
				string ipaddr = "127.0.0.1";
				_state = SessionState.Logged;

				string ret = "200 Succesfully logged in using " + info.ChallengeType;
				ret += " as " + info.UserName + " (" + fullName + ")";
				ret += " from " + ipaddr;
				return ret;
			} else if (words[0].Equals("tunnel") && _state == SessionState.Logged) {
				return "400 Not implemented yet";
			} else if (words[0].Equals("pop") && _state == SessionState.Logged) {
				return "400 Not implemented yet";
			} else {
				return "400 Unknown command: " + words[0];
			}
		}

		private string getHelpString() {
			string ret = "201 Available commands\n";

			switch (_state) {
			case SessionState.Initial:
				ret += "starttls\n";
				ret += "client <name/version> <osname/osversion>\n";
				ret += "username <nic-hdl>\n";
				break;
			case SessionState.Challenge:
				ret += "challenge clear|md5\n";
				break;
			case SessionState.Authenticate:
				ret += "authenticate clear|md5 <response>\n";
				break;
			case SessionState.Logged:
				ret += "tunnel list\n";
				ret += "tunnel show <tunnel-id>\n";
				ret += "tunnel set <tunnel-id> endpoint {<new-ipv4>|current}\n";
				ret += "tunnel set <tunnel-id> state {enabled|disabled}\n";
				ret += "pop list\n";
				ret += "pop show <pop-name>\n";
				break;
			}

			ret += "set prompt enabled|disabled\n";
			ret += "get unixtime\n";
			ret += "help\n";
			ret += "exit\n";
			ret += "quit\n";

			ret += "202 End of help";

			return ret;
		}
	}
}
