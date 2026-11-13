// Ed25519 signature VERIFICATION only (no signing, no key generation).
//
// Source: a direct port of the verification path of TweetNaCl, version
// 20140427 (https://tweetnacl.cr.yp.to/), by Daniel J. Bernstein, Bernard van
// Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers.
// TweetNaCl is in the PUBLIC DOMAIN ("TweetNaCl is a self-contained public-
// domain crypto library", tweetnacl.cr.yp.to). See NOTICE at the repo root.
//
// Every function below keeps the name and the arithmetic of its tweetnacl.c
// counterpart (car25519, sel25519, pack25519, M, inv25519, pow2523, add,
// scalarmult, modL, unpackneg, crypto_sign_open); nothing here is new curve
// math. Changes from the original, all outside the arithmetic:
//   - verify only; SHA-512 comes from System.Security.Cryptography;
//   - signature and message are passed separately (detached signature);
//   - an added S < L check (RFC 8032 section 5.1.7) refuses malleable signatures.
// Checked against the RFC 8032 section 7.1 test vectors by samples/csharp/Tests.
// Verification handles only public data, so timing side channels don't matter.
//
// Licence of this file: public domain (as its source), offered under the
// repo's MIT licence for convenience.

using System;
using System.Security.Cryptography;

namespace Perchlight.Keys
{
    public static class Ed25519
    {
        public const int PublicKeySize = 32;
        public const int SignatureSize = 64;

        static long[] Gf(params long[] init)
        {
            var r = new long[16];
            Array.Copy(init, r, init.Length);
            return r;
        }

        static readonly long[] gf0 = Gf();
        static readonly long[] gf1 = Gf(1);
        static readonly long[] D = Gf(0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203);
        static readonly long[] D2 = Gf(0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406);
        static readonly long[] X = Gf(0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169);
        static readonly long[] Y = Gf(0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666);
        static readonly long[] I = Gf(0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83);

        static readonly long[] L = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
        };

        // vn / crypto_verify_32
        static int Vn(byte[] x, int xo, byte[] y, int yo, int n)
        {
            unchecked
            {
                uint d = 0;
                for (int i = 0; i < n; i++) d |= (uint)(x[xo + i] ^ y[yo + i]);
                return (int)((1 & ((d - 1) >> 8)) - 1);
            }
        }

        static void Set25519(long[] r, long[] a)
        {
            for (int i = 0; i < 16; i++) r[i] = a[i];
        }

        static void Car25519(long[] o)
        {
            unchecked
            {
                for (int i = 0; i < 16; i++)
                {
                    o[i] += (1L << 16);
                    long c = o[i] >> 16;
                    o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
                    o[i] -= c << 16;
                }
            }
        }

        static void Sel25519(long[] p, long[] q, int b)
        {
            long c = ~(b - 1);
            for (int i = 0; i < 16; i++)
            {
                long t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        static void Pack25519(byte[] o, long[] n)
        {
            var m = new long[16];
            var t = new long[16];
            for (int i = 0; i < 16; i++) t[i] = n[i];
            Car25519(t);
            Car25519(t);
            Car25519(t);
            for (int j = 0; j < 2; j++)
            {
                m[0] = t[0] - 0xffed;
                for (int i = 1; i < 15; i++)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                int b = (int)((m[15] >> 16) & 1);
                m[14] &= 0xffff;
                Sel25519(t, m, 1 - b);
            }
            for (int i = 0; i < 16; i++)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        static int Neq25519(long[] a, long[] b)
        {
            var c = new byte[32];
            var d = new byte[32];
            Pack25519(c, a);
            Pack25519(d, b);
            return Vn(c, 0, d, 0, 32);
        }

        static byte Par25519(long[] a)
        {
            var d = new byte[32];
            Pack25519(d, a);
            return (byte)(d[0] & 1);
        }

        static void Unpack25519(long[] o, byte[] n)
        {
            for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
            o[15] &= 0x7fff;
        }

        static void A(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
        }

        static void Z(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
        }

        static void M(long[] o, long[] a, long[] b)
        {
            unchecked
            {
                var t = new long[31];
                for (int i = 0; i < 16; i++)
                    for (int j = 0; j < 16; j++)
                        t[i + j] += a[i] * b[j];
                for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
                for (int i = 0; i < 16; i++) o[i] = t[i];
                Car25519(o);
                Car25519(o);
            }
        }

        static void S(long[] o, long[] a)
        {
            M(o, a, a);
        }

        static void Inv25519(long[] o, long[] i)
        {
            var c = new long[16];
            for (int a = 0; a < 16; a++) c[a] = i[a];
            for (int a = 253; a >= 0; a--)
            {
                S(c, c);
                if (a != 2 && a != 4) M(c, c, i);
            }
            for (int a = 0; a < 16; a++) o[a] = c[a];
        }

        static void Pow2523(long[] o, long[] i)
        {
            var c = new long[16];
            for (int a = 0; a < 16; a++) c[a] = i[a];
            for (int a = 250; a >= 0; a--)
            {
                S(c, c);
                if (a != 1) M(c, c, i);
            }
            for (int a = 0; a < 16; a++) o[a] = c[a];
        }

        static long[][] NewPoint()
        {
            return new[] { new long[16], new long[16], new long[16], new long[16] };
        }

        static void Add(long[][] p, long[][] q)
        {
            long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16], t = new long[16],
                e = new long[16], f = new long[16], g = new long[16], h = new long[16];

            Z(a, p[1], p[0]);
            Z(t, q[1], q[0]);
            M(a, a, t);
            A(b, p[0], p[1]);
            A(t, q[0], q[1]);
            M(b, b, t);
            M(c, p[3], q[3]);
            M(c, c, D2);
            M(d, p[2], q[2]);
            A(d, d, d);
            Z(e, b, a);
            Z(f, d, c);
            A(g, d, c);
            A(h, b, a);

            M(p[0], e, f);
            M(p[1], h, g);
            M(p[2], g, f);
            M(p[3], e, h);
        }

        static void Cswap(long[][] p, long[][] q, int b)
        {
            for (int i = 0; i < 4; i++) Sel25519(p[i], q[i], b);
        }

        static void Pack(byte[] r, long[][] p)
        {
            long[] tx = new long[16], ty = new long[16], zi = new long[16];
            Inv25519(zi, p[2]);
            M(tx, p[0], zi);
            M(ty, p[1], zi);
            Pack25519(r, ty);
            r[31] ^= (byte)(Par25519(tx) << 7);
        }

        static void Scalarmult(long[][] p, long[][] q, byte[] s, int so)
        {
            Set25519(p[0], gf0);
            Set25519(p[1], gf1);
            Set25519(p[2], gf1);
            Set25519(p[3], gf0);
            for (int i = 255; i >= 0; --i)
            {
                int b = (s[so + i / 8] >> (i & 7)) & 1;
                Cswap(p, q, b);
                Add(q, p);
                Add(p, p);
                Cswap(p, q, b);
            }
        }

        static void Scalarbase(long[][] p, byte[] s, int so)
        {
            var q = NewPoint();
            Set25519(q[0], X);
            Set25519(q[1], Y);
            Set25519(q[2], gf1);
            M(q[3], X, Y);
            Scalarmult(p, q, s, so);
        }

        static void ModL(byte[] r, long[] x)
        {
            unchecked
            {
                long carry;
                int i, j;
                for (i = 63; i >= 32; --i)
                {
                    carry = 0;
                    for (j = i - 32; j < i - 12; ++j)
                    {
                        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                        carry = (x[j] + 128) >> 8;
                        x[j] -= carry << 8;
                    }
                    x[j] += carry;
                    x[i] = 0;
                }
                carry = 0;
                for (j = 0; j < 32; j++)
                {
                    x[j] += carry - (x[31] >> 4) * L[j];
                    carry = x[j] >> 8;
                    x[j] &= 255;
                }
                for (j = 0; j < 32; j++) x[j] -= carry * L[j];
                for (i = 0; i < 32; i++)
                {
                    x[i + 1] += x[i] >> 8;
                    r[i] = (byte)(x[i] & 255);
                }
            }
        }

        static void Reduce(byte[] r)
        {
            var x = new long[64];
            for (int i = 0; i < 64; i++) x[i] = r[i];
            for (int i = 0; i < 64; i++) r[i] = 0;
            ModL(r, x);
        }

        static int Unpackneg(long[][] r, byte[] p)
        {
            long[] t = new long[16], chk = new long[16], num = new long[16], den = new long[16],
                den2 = new long[16], den4 = new long[16], den6 = new long[16];
            Set25519(r[2], gf1);
            Unpack25519(r[1], p);
            S(num, r[1]);
            M(den, num, D);
            Z(num, num, r[2]);
            A(den, r[2], den);

            S(den2, den);
            S(den4, den2);
            M(den6, den4, den2);
            M(t, den6, num);
            M(t, t, den);

            Pow2523(t, t);
            M(t, t, num);
            M(t, t, den);
            M(t, t, den);
            M(r[0], t, den);

            S(chk, r[0]);
            M(chk, chk, den);
            if (Neq25519(chk, num) != 0) M(r[0], r[0], I);

            S(chk, r[0]);
            M(chk, chk, den);
            if (Neq25519(chk, num) != 0) return -1;

            if (Par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

            M(r[3], r[0], r[1]);
            return 0;
        }

        // Added (not in TweetNaCl): RFC 8032 5.1.7 requires 0 <= S < L.
        static bool ScalarIsCanonical(byte[] s, int so)
        {
            for (int i = 31; i >= 0; i--)
            {
                if (s[so + i] < L[i]) return true;
                if (s[so + i] > L[i]) return false;
            }
            return false; // S == L
        }

        /// <summary>
        /// Verifies a detached Ed25519 signature (RFC 8032 "pure" Ed25519).
        /// The verification steps are crypto_sign_open from TweetNaCl.
        /// </summary>
        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            if (signature == null || message == null || publicKey == null) return false;
            if (signature.Length != SignatureSize || publicKey.Length != PublicKeySize) return false;
            if (!ScalarIsCanonical(signature, 32)) return false;

            var q = NewPoint();
            if (Unpackneg(q, publicKey) != 0) return false;

            // h = SHA-512(R || A || M) mod L
            var buf = new byte[64 + message.Length];
            Array.Copy(signature, 0, buf, 0, 32);
            Array.Copy(publicKey, 0, buf, 32, 32);
            Array.Copy(message, 0, buf, 64, message.Length);
            byte[] h;
            using (var sha = SHA512.Create()) h = sha.ComputeHash(buf);
            Reduce(h);

            var p = NewPoint();
            Scalarmult(p, q, h, 0);
            Scalarbase(q, signature, 32);
            Add(p, q);
            var t = new byte[32];
            Pack(t, p);
            return Vn(signature, 0, t, 0, 32) == 0;
        }
    }
}
