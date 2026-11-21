# TODO

Every `unsupported` error baldssl reports corresponds to an entry here.
`grep -rn 'Error::unsupported\|TODO(' crates/` lists the code sites.

## commands (towards running a CA)

- [ ] `genpkey` / `ecparam -genkey`: P-256, P-384, P-521, Ed25519 key generation
      (needs a DRBG and the curve arithmetic below).
- [ ] `pkey`: read, convert and print private and public keys (PKCS#8, SEC1,
      SPKI; PEM and DER).
- [ ] `req`: CSR creation and `-x509` self-signed certificates. This is what
      completes the interop direction "baldssl creates, OpenSSL accepts".
- [ ] `x509 -req -CA -CAkey`: signing a CSR.
- [ ] `ca`: the minimal CA workflow (index, serial file, extensions).
- [ ] `verify`: chain building and signature verification.
- [ ] `version` printing OpenSSL's format, and multi-call
      (`argv[0] ==     "openssl"`) for drop-in use.

## primitives (`baldssl-crypto`)

- [ ] Field and group arithmetic for P-256, P-384, P-521 (constant time).
- [ ] ECDSA sign and verify (FIPS 186-5), deterministic nonces (RFC 6979).
- [ ] Ed25519 (RFC 8032).
- [ ] HMAC (RFC 2104), HMAC-DRBG (SP 800-90A).
- [ ] RSA PKCS#1 v1.5 and PSS verification (to read RSA-signed chains).

## `x509 -text` coverage

- [ ] Extensions OpenSSL knows that are not printed yet (currently
      `unsupported`): CRL Distribution Points, Authority Information Access,
      Certificate Policies, Name Constraints, Policy Constraints, Policy
      Mappings, Inhibit Any Policy, Subject Information Access, CT SCTs and
      precertificate poison, TLS Feature, Netscape extensions, and the rest of
      OpenSSL's `standard_exts` table.
- [ ] GeneralName `otherName` (UPN, SmtpUTF8Mailbox, ...); `DirName` with
      non-ASCII values (`X509_NAME_oneline` escaping).
- [ ] Public keys: secp256k1 and other named curves, explicit EC parameters,
      Ed448, X25519, X448, RSA-PSS keys, DSA, ML-DSA, SLH-DSA.
- [ ] RSASSA-PSS and SM2 signature parameter printing.
- [ ] `TODO(ec-point-validation)`: reject points not on the curve, as OpenSSL
      does ("Unable to load Public Key").
- [ ] v2 issuer/subject unique identifiers.
- [ ] `TRUSTED CERTIFICATE` (auxiliary trust data).
- [ ] Digests for `-fingerprint`: MD5, SHA3, SHA-512/t, SM3, BLAKE2.
- [ ] `-nameopt`, `-certopt`, `-dateopt`, `-ext`, `-purpose`, `-pubkey`,
      `-modulus`, `-email`, `-ocspid`, `-hash`.
- [ ] OID arcs above 128 bits.

## compatibility

- [ ] Decide on OpenSSL 3.0, 3.6 and 4.0 (CI runs them as informational).
- [ ] Windows `long` (LLP64) serial-number layout as an option.

## verification (Lean 4)

- [ ] Extract `baldssl-core` with Charon + Aeneas (`--cfg aeneas`).
- [ ] First theorem: `base64::decode` is total (returns `Result.ok` on every
      input, never `fail` or `div`).
