// Runs the C# sample against samples/vectors/*.json:
//   - Ed25519.Verify against the RFC 8032 section 7.1 vectors (and negatives)
//   - LicenseVerifier against the perchlight token vectors (the SDD's
//     acceptance list: valid lease accepted; changed byte, other dev, other
//     prod, unknown kid and past exp + grace rejected)
// Exit code 0 = all passed.  dotnet run --project samples/csharp/Tests

using System;
using System.Collections.Generic;
using System.IO;
using Perchlight.Keys;

namespace Perchlight.Keys.Tests
{
    static class Program
    {
        static int passed, failed;

        static void Check(bool ok, string name)
        {
            if (ok) passed++;
            else
            {
                failed++;
                Console.WriteLine("FAIL " + name);
            }
        }

        static byte[] Hex(string h)
        {
            var b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }

        static string FindVectors()
        {
            var dir = AppContext.BaseDirectory;
            for (int i = 0; i < 8 && dir != null; i++)
            {
                var p = Path.Combine(dir, "samples", "vectors");
                if (Directory.Exists(p)) return p;
                dir = Path.GetDirectoryName(dir.TrimEnd(Path.DirectorySeparatorChar));
            }
            var cwd = Path.Combine(Directory.GetCurrentDirectory(), "samples", "vectors");
            if (Directory.Exists(cwd)) return cwd;
            throw new DirectoryNotFoundException("samples/vectors not found");
        }

        static int Main()
        {
            var dir = FindVectors();

            // RFC 8032
            var rfc = (Dictionary<string, object>)MiniJson.Parse(File.ReadAllText(Path.Combine(dir, "rfc8032.json")));
            foreach (Dictionary<string, object> v in (List<object>)rfc["vectors"])
            {
                bool want = (bool)v["valid"];
                bool got = Ed25519.Verify(Hex((string)v["signature"]), Hex((string)v["message"]), Hex((string)v["public"]));
                Check(got == want, "ed25519: " + v["name"]);
            }

            // perchlight tokens
            var tv = (Dictionary<string, object>)MiniJson.Parse(File.ReadAllText(Path.Combine(dir, "tokens.json")));
            var keys = new Dictionary<string, byte[]>();
            foreach (var kv in (Dictionary<string, object>)tv["publicKeys"]) keys[kv.Key] = Hex((string)kv.Value);
            var verifier = new LicenseVerifier(keys, (string)tv["product"]);
            var now = DateTimeOffset.FromUnixTimeSeconds((long)tv["now"]);
            string device = (string)tv["device"];
            foreach (Dictionary<string, object> c in (List<object>)tv["cases"])
            {
                var types = new List<string>();
                foreach (var t in (List<object>)c["types"]) types.Add((string)t);
                var r = verifier.Verify((string)c["token"], types.ToArray(), device, now);
                Check(r.Status.ToString() == (string)c["expect"], "token: " + c["name"] + " (got " + r.Status + ")");
            }

            var valid = (string)((Dictionary<string, object>)((List<object>)tv["cases"])[0])["token"];
            var ok = verifier.Verify(valid, new[] { "lease" }, device, now);
            Check(ok.Edition == "pro" && ok.HasFeature("export") && !ok.HasFeature("nope"), "token: edition and features");
            Check(verifier.Verify(valid, new[] { "lease" }, device, now, newestSeenUnix: (long)tv["now"] + 3 * 86400).Status == VerifyStatus.ClockBehind, "token: newest-seen time ahead of the clock");
            var revokedKid = new LicenseVerifier(keys, (string)tv["product"], new[] { "rfc8032-test1" });
            Check(revokedKid.Verify(valid, new[] { "lease" }, device, now).Status == VerifyStatus.RevokedKid, "token: revoked kid");

            var revs = (Dictionary<string, object>)tv["revocations"];
            Check(verifier.IsRevoked((string)revs["token"], (string)revs["revoked"], out var s1) && s1 == VerifyStatus.Valid, "revs: revoked id listed");
            Check(!verifier.IsRevoked((string)revs["token"], (string)revs["notRevoked"], out var s2) && s2 == VerifyStatus.Valid, "revs: other id not listed");
            Check(!verifier.IsRevoked(valid, "x", out var s3) && s3 == VerifyStatus.WrongType, "revs: a lease isn't a revocation list");

            Check(DeviceId.Compute("salt", "machine").Length == 64, "device id: 64 hex characters");
            Check(LicenseVerifier.FromBase64Url("a+b") == null, "base64url: refuses '+'");

            Console.WriteLine($"{passed} passed, {failed} failed");
            return failed == 0 ? 0 : 1;
        }
    }
}
