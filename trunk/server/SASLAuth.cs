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
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Nabla {
	public delegate string SASLAuthCallback(string username);

	public class SASLAuth {
		private enum SASLMethod {
			Unsupported,
			Plain,
			DigestMD5
		}

		private string _methodString;
		private SASLMethod _method;
		private string _realm;
		private SASLAuthCallback _callback;

		private bool _finished = false;
		private bool _success = false;

		public bool Finished {
			get {
				return _finished;
			}
		}

		public bool Success {
			get {
				return _success;
			}
		}

		public SASLAuth(string method, string realm, SASLAuthCallback callback) {
			_methodString = method;
			switch (method) {
			case "PLAIN":
				_method = SASLMethod.Plain;
				break;
			case "DIGEST-MD5":
				_method = SASLMethod.DigestMD5;
				break;
			default:
				_method = SASLMethod.Unsupported;
				break;
			}
			_realm = realm;
			_callback = callback;
		}

		public static string[] GetSupportedMethods() {
			return new string[] { "PLAIN", "DIGEST-MD5" };
		}

		public string GetChallenge() {
			UInt32 nonce = (UInt32) (DateTime.UtcNow-new DateTime(1970, 1, 1)).TotalSeconds;

			switch (_method) {
			case SASLMethod.Plain:
				return "";
			case SASLMethod.DigestMD5:
				string challenge = "";
				challenge += "charset=utf-8";
				challenge += ",realm=\"" + _realm + "\"";
				challenge += ",nonce=\"" + nonce + "\"";
				challenge += ",qop=\"auth\",algorithm=md5-sess";
				return Convert.ToBase64String(Encoding.UTF8.GetBytes(challenge));
			default:
				_finished = true;
				return "300 Unsupported authentication method " + _methodString;
			}
		}

		public string GetResponse(string resp) {
			if (resp.Length > 0 && resp[0] == '\0') {
				/* Strip the null byte that Gateway6 client always sends */
				resp = resp.Substring(1);
			}

			try {
				switch (_method) {
				case SASLMethod.Plain:
					if (resp.Equals("AUTHENTICATE PLAIN")) {
						Console.WriteLine("Requesting plain authentication multiple times, ignoring");
						return null;
					}

					string[] words = resp.Split(new char[] {'\0'});
					if (words.Length == 2) {
						// This is the correct length, nothing to be done here
					} else if (words.Length == 3 && words[0].Length == 0) {
						// For some reason TCP connections have one additional '\0' in the beginning
						words = new String[] { words[1], words[2] };
					} else {
						throw new Exception("Invalid plain authentication string, length: " + words.Length);
					}

					string username = words[0].Trim();
					string password = words[1].Trim();

					Console.WriteLine("Got plain authentication with: " + username + ":" + password);

					_finished = true;
					_success = true;
					return null;
				case SASLMethod.DigestMD5:
					Dictionary<string, string> dict = new Dictionary<string, string>();
					string respString = Encoding.UTF8.GetString(Convert.FromBase64String(resp));
					string[] values = respString.Split(new char[] {','}, StringSplitOptions.RemoveEmptyEntries);
					foreach (string v in values) {
						if (v.Trim().Equals(""))
							continue;

						string key = v.Substring(0, v.IndexOf('=')).Trim();
						string value = v.Substring(v.IndexOf('=')+1).Trim();
						dict.Add(key, value);
					}

					string usernameValue = dict["username"];
					string realmValue = dict["realm"];
					string passwd = _callback(unq(usernameValue));
					if (passwd == null) {
						return "300 Invalid username or password";
					}

					string nonceValue = dict["nonce"];
					string ncValue = dict["nc"];
					string cnonceValue = dict["cnonce"];
					string digestUriValue = dict["digest-uri"];
					string responseValue = dict["response"];
					string qopValue = dict["qop"];

					MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

					/* Directly from RFC 2617 / RFC 2831 */
					string A1_1 = unq(usernameValue) + ":" + unq(realmValue) + ":" + passwd;
					byte[] HA1_1Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(A1_1));

					/* Construct A1 from raw bytes and the string */
					byte[] A1End = Encoding.UTF8.GetBytes(":" + unq(nonceValue) +
					                                      ":" + unq(cnonceValue));
					byte[] A1Bytes = new byte[HA1_1Bytes.Length + A1End.Length];
					Array.Copy(HA1_1Bytes, 0, A1Bytes, 0, HA1_1Bytes.Length);
					Array.Copy(A1End, 0, A1Bytes, HA1_1Bytes.Length, A1End.Length);

					/* Calculate H(A1) */
					byte[] HA1Bytes = md5.ComputeHash(A1Bytes);
					string HA1 = BitConverter.ToString(HA1Bytes).Replace("-", "").ToLower();

					string A2 = "AUTHENTICATE:" + unq(digestUriValue);
					string cA2 = ":" + unq(digestUriValue);
					if (qopValue.Equals("auth-int")) {
						A2 += ":00000000000000000000000000000000";
						cA2 += ":00000000000000000000000000000000";
					}

					byte[] HA2Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(A2));
					string HA2 = BitConverter.ToString(HA2Bytes).Replace("-", "").ToLower();
					byte[] cHA2Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(cA2));
					string cHA2 = BitConverter.ToString(cHA2Bytes).Replace("-", "").ToLower();

					string digestString =
						HA1 + ":" + unq(nonceValue) + ":" + ncValue + ":" +
						unq(cnonceValue) + ":" + unq(qopValue) + ":" + HA2;
					byte[] digestBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(digestString));
					string digest = BitConverter.ToString(digestBytes).Replace("-", "").ToLower();

					if (!digest.Equals(responseValue)) {
						_finished = true;
						return "300 Invalid username or password";
					}

					digestString =
						HA1 + ":" + unq(nonceValue) + ":" + ncValue + ":" +
						unq(cnonceValue) + ":" + unq(qopValue) + ":" + cHA2;
					digestBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(digestString));
					digest = BitConverter.ToString(digestBytes).Replace("-", "").ToLower();

					byte[] rspBytes = Encoding.UTF8.GetBytes("rspauth=" + digest);
					string rspauth = Convert.ToBase64String(rspBytes);

					_finished = true;
					_success = true;
					return rspauth;
				}
			} catch (Exception e) {
				Console.WriteLine(e);
			}

			_finished = true;
			return "300 Error parsing challenge response";
		}

		private string unq(string str) {
			if (str[0] == '"' && str[str.Length-1] == '"')
				return str.Substring(1, str.Length-2);
			else
				return str;
		}
	}
}
