/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009-2010  Juho Vähä-Herttua
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
		/* List to keep track of currently used method */
		private enum SASLMethod {
			Unsupported,
			Plain,
			DigestMD5
		}

		/* Authentication method in both string and enum form */
		private string _methodString;
		private SASLMethod _method;

		/* Realm string and callback to get the password */
		private string _realm;
		private SASLAuthCallback _callback;

		private bool _finished = false;  // Indicates a finished authentication
		private bool _success = false;   // Indicates a successful password match

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

		/* List methods that are supported by the code */
		public static string[] GetSupportedMethods() {
			return new string[] { "PLAIN", "DIGEST-MD5" };
		}

		/* Create a new SASL session with method, realm and callback */
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

		/* Get challenge for the authentication */
		public string GetChallenge() {
			UInt32 nonce = (UInt32) (DateTime.UtcNow-new DateTime(1970, 1, 1)).TotalSeconds;

			switch (_method) {
			case SASLMethod.Plain:
				return null;
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

		/* Get response for the authentication, takes challenge response as input */
		public string GetResponse(string resp) {
			try {
				switch (_method) {
				case SASLMethod.Plain:
					string[] words = resp.Split(new char[] {'\0'});
					if (words.Length != 2) {
						_finished = true;
						return "300 Invalid authentication string count: " + words.Length;
					}

					string username = words[0].Trim();
					string password = words[1].Trim();

					string dbpass = _callback(username);
					if (dbpass == null || !dbpass.Equals(password)) {
						_finished = true;
						return "300 Invalid username or password";
					}

					_finished = true;
					_success = true;
					return null;
				case SASLMethod.DigestMD5:
					/* Create a dictionary where all SASL parameters are added */
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

					/* Find the username and fetch the corresponding password */
					string usernameValue = dict["username"];
					string realmValue = dict["realm"];
					string passwd = _callback(unq(usernameValue));
					if (passwd == null) {
						_finished = true;
						return "300 Invalid username or password";
					}

					/* Get other used values from the dictionary */
					string nonceValue = dict["nonce"];
					string ncValue = dict["nc"];
					string cnonceValue = dict["cnonce"];
					string digestUriValue = dict["digest-uri"];
					string responseValue = dict["response"];
					string qopValue = dict["qop"];

					/* Directly from RFC 2617 / RFC 2831 */
					MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
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

					/* Check that our digest equals the response we got from server */
					if (!digest.Equals(responseValue)) {
						_finished = true;
						return "300 Invalid username or password";
					}

					/* Construct the final response digest using cHA2 instead of HA2 */
					digestString =
						HA1 + ":" + unq(nonceValue) + ":" + ncValue + ":" +
						unq(cnonceValue) + ":" + unq(qopValue) + ":" + cHA2;
					digestBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(digestString));
					digest = BitConverter.ToString(digestBytes).Replace("-", "").ToLower();

					/* Get the response string from the response digest */
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

		/* Remove doublequotes from the string if present */
		private string unq(string str) {
			if (str[0] == '"' && str[str.Length-1] == '"')
				return str.Substring(1, str.Length-2);
			else
				return str;
		}
	}
}
