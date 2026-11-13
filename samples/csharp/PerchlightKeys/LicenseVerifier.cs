// perchlight-keys offline verifier for C# (.NET, Unity).
//
// NOT FOR UNITY ASSET STORE PACKAGES. The Asset Store's submission rules
// forbid DRM and licence checks in store assets. Use this for products sold
// outside the Asset Store (your own site, itch.io, Gumroad, Lemon Squeezy,
// Stripe) and for finished games and standalone apps.
//
// Threat model: every check that runs on the buyer's machine can be patched
// out. Signing stops forged keys and casual sharing; it doesn't stop someone
// who edits your binary. No obfuscation is included, on purpose.
//
// Format: docs/FORMAT.md. Test vectors: samples/vectors/. MIT licence.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Perchlight.Keys
{
    public enum VerifyStatus
    {
        Valid,
        Malformed,
        UnknownKid,
        RevokedKid,
        BadSignature,
        WrongType,
        WrongProduct,
        WrongDevice,
        NotYetValid,
        Expired,
        ClockBehind,
    }

    public sealed class VerifyResult
    {
        public VerifyStatus Status { get; internal set; }
        public bool IsValid => Status == VerifyStatus.Valid;
        /// <summary>The payload, when the signature checked out (even if a later check failed).</summary>
        public IReadOnlyDictionary<string, object> Payload { get; internal set; }

        public string Type => Get("typ") as string;
        public string LicenseId => Get("lid") as string;
        public string Edition => Get("ed") as string;
        public long? ExpiresUnix => Get("exp") as long?;
        public long? RenewAfterUnix => Get("renew") as long?;

        public IReadOnlyList<string> Features
        {
            get
            {
                var list = new List<string>();
                if (Get("feat") is List<object> f)
                    foreach (var x in f) if (x is string s) list.Add(s);
                return list;
            }
        }

        public bool HasFeature(string name)
        {
            foreach (var f in Features) if (f == name) return true;
            return false;
        }

        object Get(string k)
        {
            return Payload != null && Payload.TryGetValue(k, out var v) ? v : null;
        }

        internal static VerifyResult Fail(VerifyStatus s, Dictionary<string, object> p = null)
        {
            return new VerifyResult { Status = s, Payload = p };
        }
    }

    /// <summary>
    /// Checks licence files ("lic"), leases ("lease"), trial leases ("trial") and
    /// revocation lists ("revs") offline, against public keys embedded in the app.
    /// </summary>
    public sealed class LicenseVerifier
    {
        const string Domain = "perchlight-keys/v1\n";
        readonly Dictionary<string, byte[]> keys;
        readonly HashSet<string> revokedKids;
        readonly string product;

        /// <summary>Clock slack for nbf/exp/iat checks (the SDD's +-24 h).</summary>
        public TimeSpan Slack { get; set; } = TimeSpan.FromHours(24);

        /// <param name="publicKeys">kid -> 32-byte Ed25519 public key (embed every kid you still trust).</param>
        /// <param name="product">Your product id from keys.json.</param>
        /// <param name="revokedKids">kids withdrawn after a compromise (from a newer app build or a revs list).</param>
        public LicenseVerifier(IDictionary<string, byte[]> publicKeys, string product, IEnumerable<string> revokedKids = null)
        {
            keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var kv in publicKeys)
            {
                if (kv.Value == null || kv.Value.Length != Ed25519.PublicKeySize) throw new ArgumentException("public keys must be 32 bytes");
                keys[kv.Key] = kv.Value;
            }
            this.product = product ?? throw new ArgumentNullException(nameof(product));
            this.revokedKids = new HashSet<string>(revokedKids ?? Array.Empty<string>(), StringComparer.Ordinal);
        }

        /// <summary>
        /// Verifies a token. expectedTypes: e.g. "lease", "trial" (a lease check usually
        /// accepts both), or "lic". deviceId: this device's id hash (leases and trials).
        /// newestSeenUnix: the newest server time this app has stored (catches clock rewinds; 0 = none).
        /// </summary>
        public VerifyResult Verify(string token, string[] expectedTypes, string deviceId, DateTimeOffset now, long newestSeenUnix = 0)
        {
            var parsed = ParseAndCheckSignature(token, out var status);
            if (parsed == null) return VerifyResult.Fail(status);

            string typ = parsed["typ"] as string;
            if (Array.IndexOf(expectedTypes, typ) < 0) return VerifyResult.Fail(VerifyStatus.WrongType, parsed);
            if (!(parsed.TryGetValue("prod", out var prod) && prod as string == product)) return VerifyResult.Fail(VerifyStatus.WrongProduct, parsed);
            if (typ == "lease" || typ == "trial")
            {
                if (!(parsed.TryGetValue("dev", out var dev) && dev is string d && d == deviceId)) return VerifyResult.Fail(VerifyStatus.WrongDevice, parsed);
            }

            long nowS = now.ToUnixTimeSeconds();
            long slack = (long)Slack.TotalSeconds;
            long iat = parsed.TryGetValue("iat", out var iv) && iv is long li ? li : 0;
            if (iat > nowS + slack || newestSeenUnix > nowS + slack) return VerifyResult.Fail(VerifyStatus.ClockBehind, parsed);
            long nbf = parsed.TryGetValue("nbf", out var nv) && nv is long ln ? ln : 0;
            if (nowS + slack < nbf) return VerifyResult.Fail(VerifyStatus.NotYetValid, parsed);
            if (parsed.TryGetValue("exp", out var ev) && ev is long exp)
            {
                long grace = parsed.TryGetValue("grace", out var gv) && gv is long lg ? lg : 0;
                if (nowS > exp + grace + slack) return VerifyResult.Fail(VerifyStatus.Expired, parsed);
            }
            else if (typ != "lic")
            {
                // Only licence files may be perpetual (exp null); a lease always expires.
                return VerifyResult.Fail(VerifyStatus.Malformed, parsed);
            }
            return new VerifyResult { Status = VerifyStatus.Valid, Payload = parsed };
        }

        /// <summary>Verifies a revocation list and says whether a licence id is on it.</summary>
        public bool IsRevoked(string revsToken, string licenseId, out VerifyStatus status)
        {
            var p = ParseAndCheckSignature(revsToken, out status);
            if (p == null) return false;
            if (p["typ"] as string != "revs") { status = VerifyStatus.WrongType; return false; }
            if (!(p.TryGetValue("prod", out var prod) && prod as string == product)) { status = VerifyStatus.WrongProduct; return false; }
            status = VerifyStatus.Valid;
            if (p.TryGetValue("lids", out var l) && l is List<object> lids)
                foreach (var x in lids) if (x as string == licenseId) return true;
            return false;
        }

        Dictionary<string, object> ParseAndCheckSignature(string token, out VerifyStatus status)
        {
            status = VerifyStatus.Malformed;
            if (string.IsNullOrEmpty(token) || token.Length > 8192) return null;
            var parts = token.Trim().Split('.');
            if (parts.Length != 3 || parts[0] != "PLK1") return null;
            byte[] payloadBytes = FromBase64Url(parts[1]);
            byte[] sig = FromBase64Url(parts[2]);
            if (payloadBytes == null || sig == null || sig.Length != Ed25519.SignatureSize) return null;

            Dictionary<string, object> p;
            try
            {
                p = MiniJson.Parse(new UTF8Encoding(false, true).GetString(payloadBytes)) as Dictionary<string, object>;
            }
            catch (Exception)
            {
                return null;
            }
            if (p == null || !(p.TryGetValue("typ", out var t) && t is string typ) || !(p.TryGetValue("kid", out var k) && k is string kid)) return null;

            if (revokedKids.Contains(kid)) { status = VerifyStatus.RevokedKid; return null; }
            if (!keys.TryGetValue(kid, out var pub)) { status = VerifyStatus.UnknownKid; return null; }

            byte[] head = Encoding.UTF8.GetBytes(Domain + typ + "\n");
            var msg = new byte[head.Length + payloadBytes.Length];
            Buffer.BlockCopy(head, 0, msg, 0, head.Length);
            Buffer.BlockCopy(payloadBytes, 0, msg, head.Length, payloadBytes.Length);
            if (!Ed25519.Verify(sig, msg, pub)) { status = VerifyStatus.BadSignature; return null; }
            status = VerifyStatus.Valid;
            return p;
        }

        public static byte[] FromBase64Url(string s)
        {
            if (s == null) return null;
            foreach (char c in s)
                if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')) return null;
            string t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4)
            {
                case 1: return null;
                case 2: t += "=="; break;
                case 3: t += "="; break;
            }
            try { return Convert.FromBase64String(t); } catch (FormatException) { return null; }
        }
    }

    public static class DeviceId
    {
        /// <summary>
        /// SHA-256(appSalt || platformId) as lower-case hex: the device id the server sees.
        /// platformId: e.g. Unity's SystemInfo.deviceUniqueIdentifier, or the OS machine id.
        /// It can be spoofed; that's accepted by the threat model.
        /// </summary>
        public static string Compute(string appSalt, string platformId)
        {
            using (var sha = SHA256.Create())
            {
                var h = sha.ComputeHash(Encoding.UTF8.GetBytes(appSalt + platformId));
                var sb = new StringBuilder(64);
                foreach (var b in h) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }
    }
}
