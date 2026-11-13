# perchlight-keys token format (v1)

Everything an app needs to verify licence files, leases, trial leases and revocation lists **offline**, in any language. The C# sample (`samples/csharp/`) implements this; the test vectors in `samples/vectors/` let you check another implementation.

## Token

```
PLK1.<base64url(payload)>.<base64url(signature)>
```

- base64url without padding (RFC 4648 section 5).
- `payload` is UTF-8 JSON (an object). Parse it only after the signature checks out... except to read `typ` and `kid`, which you need to check the signature.
- `signature` is 64 bytes of Ed25519 (RFC 8032, pure Ed25519, no prehash, no context) over:

```
"perchlight-keys/v1\n" || typ || "\n" || payload bytes
```

where `typ` is the payload's `typ` string and the payload bytes are exactly the decoded middle part (don't re-serialise the JSON). The prefix and `typ` are domain separation: a revocation list can't be passed off as a licence, and a v1 signature can't be reused by a later format.

## Payload fields

| Field | Types | Meaning |
|---|---|---|
| `typ` | all | `lic` (licence file), `lease` (device lease), `trial` (trial lease), `revs` (revocation list) |
| `kid` | all | Which public key signed it. Unknown or withdrawn kid = reject. |
| `lid` | lic, lease | Licence id (not the key). `null` on trials. |
| `prod` | all | Product id from `keys.json`. Must equal your product. |
| `ed`, `feat` | lic, lease, trial | Edition and its feature strings. |
| `iat`, `nbf`, `exp` | lic, lease, trial | Unix seconds. `exp` is `null` only on perpetual licence files. |
| `dev` | lease, trial | The device id hash the lease is bound to. Must equal yours. |
| `renew` | lease | Try to renew after this time (seconds). `null` on trials. |
| `grace` | lic, lease, trial | Seconds of offline use allowed after `exp`. |
| `lids`, `kids_revoked`, `since`, `more`, `next_since` | revs | Revoked licence ids since `since`; withdrawn signing kids; paging. |

Unknown fields must be ignored (later v1 servers may add some).

## Checks, in order

1. Split on `.`; the first part is `PLK1`; decode the other two; the signature is 64 bytes.
2. Read `typ` and `kid`. Reject a kid you don't embed or have withdrawn.
3. Verify the signature over the domain-separated message above.
4. `typ` is one you expect here (a lease check usually accepts `lease` and `trial`).
5. `prod` is your product.
6. Leases and trials: `dev` equals this device's id.
7. Time, with a slack of 24 hours: `nbf - slack <= now <= exp + grace + slack`. A lease or trial with `exp: null` is malformed.
8. Clock rewind (cheap check): reject if `iat > now + slack`, or if the newest server time you've stored is later than `now + slack`.

## Device id

`SHA-256(appSalt || platformId)` as lower-case hex (64 characters), computed by the app. The server accepts 16-128 characters of `A-Z a-z 0-9 _ -` and stores only this value.

## Licence keys

`<PREFIX>-` then 26 Crockford base32 symbols (`0-9 A-Z` without `I L O U`; 128 random bits in 130, so the first symbol is `0-7`) in groups of 5, then one check symbol: the 130-bit value mod 37, written with `0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U`. Example: `MYAPP-7K2QM-ZD0A4-RT8VX-W3NBC-PF9HS-1N`. Input is case-insensitive, ignores spaces and dashes, reads `O` as `0` and `I`/`L` as `1`. An app can check the check symbol before any network call; the key itself grants nothing offline.

## Test vectors

- `samples/vectors/rfc8032.json`: Ed25519 verification vectors (RFC 8032 section 7.1 tests 1-3, negatives including `S + L`, and longer messages). All hex.
- `samples/vectors/tokens.json`: tokens signed with the RFC 8032 TEST 1 key (a published test key) under kid `rfc8032-test1`, with the `now`, `product` and `device` to verify them against and the expected verdict for each (`Valid`, `BadSignature`, `WrongDevice`, `WrongProduct`, `UnknownKid`, `Expired`, `ClockBehind`, `WrongType`, `Malformed`), plus a revocation list.

`npm run vectors` regenerates them (deterministically); `npm test` checks the Worker's signer writes the valid lease byte for byte.
