/*
CodeBit Metadata

&name=Bredd.net/SessionToken
&description="Classes to create, read, and validate secure session tokens."
&author="Brandt Redd"
&url=https://raw.githubusercontent.com/bredd/AzureFunctions.AccessControl/main/SessionToken.cs
&version=1.0.1
&keywords=CodeBit
&datePublished=2023-10-24
&license=https://opensource.org/licenses/BSD-3-Clause

About Codebits: http://www.filemeta.org/CodeBit
*/

/*
=== BSD 3 Clause License ===
https://opensource.org/licenses/BSD-3-Clause

Copyright 2023 Brandt Redd

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using System.Globalization;
using System.Security.Permissions;
using System.Text;
using System.Net;
using System.Web;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System.Linq;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;

namespace Bredd.Security
{
    /// <summary>
    /// Status of a <see cref="SessionToken"/> after decoding.
    /// </summary>
    enum SessionTokenStatus
    {
        None = 0,
        Invalid = 1,
        Expired = 2,
        KeyNotFound = 3,
        OriginMismatch = 4,
        Valid = 5
    };

    class SessionTokenManager
    {
        const int c_defaultExpirationMinutes = 30;

        public const int KeyIdLimit = 32;
        public const int KeySize = 32; // In bytes

        int m_newestKeyId = 0;
        SessionTokenKey[] m_keys = new SessionTokenKey[KeyIdLimit];

        static Encoding Utf8NoBom = new UTF8Encoding(false);

        public SessionTokenManager()
        {
            DefaultExpiration = TimeSpan.FromMinutes(c_defaultExpirationMinutes);
        }

        /// <summary>
        /// Add a key to the keyset.
        /// </summary>
        /// <param name="key">Key to add to the keyset.</param>
        /// <remarks>
        /// <para>If an existing key has the same ID, the existing key is replaced.
        /// </para>
        /// </remarks>
        public void AddKey(SessionTokenKey key)
        {
            m_keys[key.Id] = key;
            if (m_keys[m_newestKeyId] is null
                || key.Created >= m_keys[m_newestKeyId].Created)
            {
                m_newestKeyId = key.Id;
            }
        }

        // This is equivalent to RandomNumberGenerator.GetBytes() which is available in .net 8 and later
        static byte[] RandomNumberGenerator_GetBytes(int count)
        {
            var rng = new RNGCryptoServiceProvider();
            var keyBytes = new byte[count];
            rng.GetBytes(keyBytes);
            return keyBytes;
        }

        /// <summary>
        /// Create and add a key to the keyset.
        /// </summary>
        /// <remarks>
        /// The ID of the new key is one higher than the newest key mod KeyIdLimit 
        /// </remarks>
        public SessionTokenKey CreateKey()
        {
            int id = (m_newestKeyId + 1) % KeyIdLimit;
            var key = new SessionTokenKey(id, RandomNumberGenerator_GetBytes(KeySize), DateTime.UtcNow);
            AddKey(key);
            return key;
        }

        /// <summary>
        /// Create a new key and remove all keys but the most recent two.
        /// </summary>
        public void RotateKeys()
        {
            // Remove everything but the most recent key.
            for (int i=0; i<KeyIdLimit; ++i)
            {
                if (i != m_newestKeyId) m_keys[i] = null;
            }
            CreateKey();
        }

        /// <summary>
        /// The number of keys in the keystore
        /// </summary>
        public int KeyCount
        {
            get
            {
                int count = 0;
                for (int i = 0; i < KeyIdLimit; ++i)
                {
                    if (!(m_keys[i] is null)) count++;
                }
                return count;
            }
        }

        public SessionTokenKey NewestKey
        {
            get
            {
                return m_keys[m_newestKeyId];
            }
        }

        /// <summary>
        /// Get all key
        /// </summary>
        /// <returns>An array of keys.</returns>
        /// <remarks>
        /// If <see cref="RotateKeys"/> is being used, there will typically be only one or two keys.
        /// </remarks>
        public SessionTokenKey[] GetKeys()
        {
            var keys = new SessionTokenKey[KeyCount];
            int c = 0;
            for (int i=0; i<KeyIdLimit; ++i)
            {
                if (!(m_keys[i] is null)) keys[c++] = m_keys[i];
            }
            return keys;
        }

        // The default expiration timespan
        public TimeSpan DefaultExpiration { get; set; }

        /// <summary>
        /// Encode a secure token into a string.
        /// </summary>
        /// <param name="token">The token to encode.</param>
        /// <returns>The encoded token.</returns>
        /// <remarks>
        /// If the expiration of the inbound token is zero, updates to the default
        /// expiration period (<see cref="DefaultExpiration"/>) from now.
        /// </remarks>
        public string SignToken(SessionToken token)
        {
            SetZeroToDefaultExpiration(token);
            return AddSignature(ComposeToken(token), token.Expiration);
        }

        /// <summary>
        /// Returns an updated token string that uses the current default expiration.
        /// </summary>
        /// <param name="token">The token to update.</param>
        /// <returns>The stringized token</returns>
        /// <remarks>
        /// <para>The expiration and key id of the inbound token are unchanged. The encoded token
        /// uses the current <see cref="DefaultExpiration"/> and <see cref="DefaultKeyId"/>.
        /// </para>
        /// <para>To determine when the new key will expire, use <see cref="RefreshEx"/>.
        /// </para>
        /// </remarks>
        public string Refresh(SessionToken token)
        {
            var newExpiration = DateTime.UtcNow.Add(DefaultExpiration);
            return AddSignature(ComposeToken(token), newExpiration);
        }

        /// <summary>
        /// Returns an updated token string that uses the current default expiration.
        /// </summary>
        /// <param name="token">The token to update.</param>
        /// <returns>The stringized token</returns>
        /// <remarks>
        /// <para>The expiration and key id of the inbound token are unchanged. The encoded token
        /// uses the current <see cref="DefaultExpiration"/> and <see cref="DefaultKeyId"/>.
        /// </para>
        /// </remarks>
        public (string token, DateTime expiration) RefreshEx(SessionToken token)
        {
            var newExpiration = DateTime.UtcNow.Add(DefaultExpiration);
            return (AddSignature(ComposeToken(token), newExpiration), newExpiration);
        }

        /// <summary>
        /// Decode and validate a secure token from a string.
        /// </summary>
        /// <param name="value">The string to decode.</param>
        /// <returns>The decoded token (whether valid or not).</returns>
        /// <remarks>
        /// Be sure to check the <see cref="SessionToken.IsValid"/> value to determine
        /// if the token is valid.
        /// </remarks>
        public SessionToken Decode(string value)
        {
            var token = new SessionToken();
            token.Status = SessionTokenStatus.Invalid; // Default to invalid until it's found to be better than that
            if (string.IsNullOrEmpty(value))
            {
                return token;
            }

            // Validate the MAC and retrieve the query string
            SessionTokenStatus macStatus = SessionTokenStatus.Invalid;
            string query = value;
            int macPos = value.LastIndexOf("&m=");
            if (macPos > 0 && value.Length - macPos >= 6)
            {
                query = value.Substring(0, macPos);

                char c = value[macPos + 3];
                int keyId = (c <= '9') ? c - '0' : (c - 'A') + 10;

                if (keyId >= 0 && keyId < KeyIdLimit)
                {
                    if (m_keys[keyId] is null)
                    {
                        macStatus = SessionTokenStatus.KeyNotFound;
                    }

                    var mac = WebEncoders.Base64UrlDecode(value.Substring(macPos + 4));
                    var match = GenerateMac(m_keys[keyId], query);
                    if (mac.SequenceEqual(match))
                    {
                        macStatus = SessionTokenStatus.Valid;
                    }
                }
            }

            // Get the expiration
            int expPos = query.LastIndexOf("&x=");
            if (expPos > 0)
            {
                if (query.Length - expPos >= 7)
                {
                    token.Expiration = ParseDate(query, expPos + 3);
                }
                query = query.Substring(0, expPos);
            }

            // Get the key-value pairs
            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var keyvalue = part.Split('=');
                if (keyvalue.Length == 2)
                {
                    token.Add(keyvalue[0], WebUtility.UrlDecode(keyvalue[1]));
                }
            }

            // Finalize status
            SessionTokenStatus expStatus = (token.Expiration > DateTime.UtcNow) ? SessionTokenStatus.Valid : SessionTokenStatus.Expired;
            token.Status = (expStatus < macStatus) ? expStatus : macStatus;

            return token;
        }

        // If expiration is zero (DateTime.MinValue) set to default expiration.
        private void SetZeroToDefaultExpiration(SessionToken token)
        {
            if (token.Expiration == DateTime.MinValue)
            {
                token.Expiration = DateTime.UtcNow.Add(DefaultExpiration);
            }
        }

        // Compose a token into string form, not including expiration, keyid, or signature
        private static string ComposeToken(IEnumerable<KeyValuePair<string, string>> values)
        {
            // Get the arguments into sorted order
            var list = new List<KeyValuePair<string, string>>(values);
            list.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));

            // Build it as a URL query string
            var sb = new StringBuilder();
            foreach (var pair in list)
            {
                if (sb.Length > 0) sb.Append('&');
                sb.Append(pair.Key);
                sb.Append('=');
                sb.Append(WebUtility.UrlEncode(pair.Value));
            }

            return sb.ToString();
        }

        // Add expiration and MAC signature to a token.
        private string AddSignature(string token, DateTime expiration)
        {
            // Add expiration
            string rawToken = string.Concat(token, "&x=", expiration.ToUniversalTime().ToString("yyyyMMddTHHmmssZ"));

            var key = m_keys[m_newestKeyId];
            if (key is null) throw new InvalidOperationException("SignedToken: No keys set - cannot encode token.");

            // Generate the MAC code
            byte[] mac = GenerateMac(key, rawToken);
            var keyId = key.Id;

            // Generate the key ID character
            string keyIdStr = ((char)((keyId < 10) ? '0' + keyId : 'A' + (keyId - 10))).ToString();

            // Return the token with expiration and MAC
            return string.Concat(rawToken, "&m=", keyIdStr, WebEncoders.Base64UrlEncode(mac));
        }

        // Generate the MAC signature for a token
        private byte[] GenerateMac(SessionTokenKey key, string value)
        {
            var bytes = Utf8NoBom.GetBytes(value);
            var hmac = new HMACSHA256(key.Key);
            return hmac.ComputeHash(bytes);
        }

        // Parse a compact expiration date
        private static DateTime ParseDate(string value, int offset)
        {
            // yyyyMMddTHHmmssZ
            try
            {
                return new DateTime(
                    ParseInt(value, offset+0, 4), // year
                    ParseInt(value, offset + 4, 2), // month
                    ParseInt(value, offset + 6, 2), // day
                    ParseInt(value, offset + 9, 2), // hour
                    ParseInt(value, offset + 11, 2), // minute
                    ParseInt(value, offset + 13, 2), // second
                    DateTimeKind.Utc);
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        // Parse an inline integer
        private static int ParseInt(string value, int offset, int length)
        {
            int result = 0;
            for (int i=0; i<length; ++i)
            {
                int cv = value[offset + i] - '0';
                if (cv > 9) cv = 9;
                result = (result * 10) + cv;
            }
            return result;
        }
    }

    class SessionTokenKey
    {
        const DateTimeStyles c_dateParseStyles = DateTimeStyles.RoundtripKind | DateTimeStyles.AllowWhiteSpaces;

        public SessionTokenKey(int id, byte[] key, DateTime created)
        {
            if (id < 0 || id > SessionTokenManager.KeyIdLimit) throw new ArgumentException("Out of range", "id");
            if (key.Length != SessionTokenManager.KeySize) throw new ArgumentException("Wrong Size", "key");
            Id = id; Key = key; Created = created;
        }

        public SessionTokenKey(string serializedKey)
        {
            var parts = serializedKey.Split('|');
            Id = int.Parse(parts[0]);
            Key = WebEncoders.Base64UrlDecode(parts[1]);
            Created = DateTime.Parse(parts[2], CultureInfo.InvariantCulture, c_dateParseStyles);
            if (Id < 0 || Id > SessionTokenManager.KeyIdLimit) throw new ArgumentException("Out of range", "id");
            if (Key.Length != SessionTokenManager.KeySize) throw new ArgumentException("Wrong Size", "key");
        }

        public int Id { get; private set; }
        public byte[] Key { get; private set;}
        public DateTime Created { get; private set; }

        public override string ToString()
        {
            return $"{Id:d2}|{WebEncoders.Base64UrlEncode(Key)}|{Created.ToString("O", CultureInfo.InvariantCulture)}";
        }
    }

    /// <summary>
    /// The pre-encoded or decoded form of a secure token. A collection of name-value
    /// pairs plus expiration and validity flag.
    /// </summary>
    class SessionToken : Dictionary<string, string>
    {
        /// <summary>
        /// Status of the token.
        /// </summary>
        /// <remarks>
        /// <para>Retains the value from when the token was decoded. So, if it expires later, the
        /// status will not change.
        /// </para>
        /// </remarks>
        public SessionTokenStatus Status { get; set; }

        /// <summary>
        /// True if the token is validated and unexpired. Only meaningful after
        /// decoding.
        /// </summary>
        /// <remarks>Change the value by setting <see cref="Status"/></remarks>
        public bool IsValid => Status == SessionTokenStatus.Valid;

        /// <summary>
        /// The DateTime when the token expires. Resolution (after round-trip) is one second.
        /// </summary>
        public DateTime Expiration { get; set; }

        /// <summary>
        /// The <see cref="TimeSpan"/> between now and when the token expires. If negative the token has already expired.
        /// </summary>
        public TimeSpan ExpiresIn
        {
            get
            {
                return Expiration - DateTime.UtcNow;
            }

            set
            {
                Expiration = DateTime.UtcNow.Add(value);
            }
        }

    }
}
