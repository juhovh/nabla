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
	public class SASLAuth {
		private enum SASLMethod {
			Unsupported,
			Plain,
			DigestMD5
		}

		private SASLMethod _method;
		private string _realm;

		private bool _finished = false;
		private bool _success = false;

		public SASLAuth(string method, string realm) {
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
		}

		public string[] GetSupportedMethods() {
			return new string[] { "PLAIN", "DIGEST-MD5" };
		}

		public string GetChallenge() {
			UInt32 nonce = (UInt32) (DateTime.UtcNow-new DateTime(1970, 1, 1)).TotalSeconds;

			switch (_method) {
			case SASLMethod.Plain:
				return null;
			case SASLMethod.DigestMD5:
				string challenge = "";
				challenge += "realm=\"" + _realm + "\"";
				challenge += ",nonce=\"" + nonce + "\"";
				challenge += ",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
				return Convert.ToBase64String(Encoding.UTF8.GetBytes(challenge));
			default:
				_finished = true;
				return "300 Unsupported authentication method";
			}
		}

		public string GetResponse(string resp) {
			try {
				switch (_method) {
				case SASLMethod.Plain:
					/* FIXME: Implement plain checking */ 
					return "200 Authentication successful";
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
					string passwd = "salasana"; // XXX: Fix to be correct

					string digestUriValue = dict["digest-uri"];
					string qopValue = dict["qop"];

					/* Directly from RFC 2617 / RFC 2831 */
					string A1 = unq(usernameValue) + ":" + unq(realmValue) + ":" + passwd;
					string A2 = "AUTHENTICATE:" + digestUriValue;
					if (qopValue.Equals("auth-int"))
						A2 += ":00000000000000000000000000000000";

					MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
					byte[] HA1Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(A1));
					string HA1 = BitConverter.ToString(HA1Bytes).Replace("-", "").ToLower();
					byte[] HA2Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(A2));
					string HA2 = BitConverter.ToString(HA2Bytes).Replace("-", "").ToLower();

					string digestString =
						HA1 + ":" + unq(nonceValue) + ":" + ncValue + ":" +
						unq(cnonceValue) + ":" + unq(qopValue) + ":" + HA1;
					byte[] digestBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(digestString));
					string digest = BitConverter.ToString(digestBytes).Replace("-", "").ToLower();

					return digest + "\r\n200 Success";
				}
			} catch (Exception) {}

			_finished = true;
			return "300 Error parsing challenge response";
		}

		private string unq(string str) {
			/* FIXME: Implement unquote */
			return str;
		}
	}
}
