# XMXX-CORE wire protocol

Reference wire formats for a Foundation `monero-signer` server, extracted from
the OZARUMOTO `xmxx` KeyOS app. All payloads are short text strings meant to
survive QR encoding (animated UR or static), USB vendor transport, or the QLv2
relay. The crypto is built on **monero-oxide / monero-wallet** (Luke Parker,
Cypher Stack audit May 2025) — the primitives are vetted, not reconstructed.

## Messages

### `xmr-address`

Derive a Monero address (optionally a subaddress) from a seed. Never returns
private keys.

```
request:  xmr-address:<account>[:<major>:<minor>]
response: monero:<address>
```

- `<account>` — SLIP-0010 account index `m/44'/128'/account'` (the xmxx wallet slot).
- `<major>:<minor>` — optional subaddress index (account, address).
- `<address>` — 95-char mainnet address (starts with `4`).

Derivation (verified against mainline Monero and the Trezor/Ledger standard):

```
account_key = SLIP-0010 m/44'/128'/<account>' from the seed
spend       = sc_reduce32(account_key)
view        = sc_reduce32(keccak256(spend))
address     = 0x12 ‖ spend_pub ‖ view_pub ‖ keccak256(checksum)  → base58
```

Subaddress construction matches `monero/src/device/device_default.cpp`:
`m = H_s("SubAddr\0" ‖ view_priv ‖ major_LE32 ‖ minor_LE32)`, `D = B + m·G`,
`C = a·D`. A wallet derived this way is fully restorable in monero-wallet-cli,
Feather, or Cake: the reduced spend scalar encodes to Monero's own 25-word
mnemonic (see `wallet::spend_mnemonic`).

Implementation: `wallet::MoneroWallet::derive` / `::subaddress` / `::spend_mnemonic`.

### Integrated addresses / payment IDs

Monero mainnet integrated addresses (network byte `0x13`) embed an 8-byte
payment ID between the public keys and the checksum (77 bytes total). The
on-chain destination is the **same** spend/view public keys as the standard
address — the payment ID is only carried in the tx extra when sending.

```
integrated = 0x13 ‖ spend_pub(32) ‖ view_pub(32) ‖ payment_id(8) ‖ keccak256(checksum)
```

- `validate_address` accepts `0x13` integrated addresses (77 bytes) in addition
  to standard (`0x12`) and subaddress (`0x2A`).
- `integrated_payment_id(addr) -> Option<[u8;8]>` returns the embedded payment
  ID.
- On the send path, signing an integrated destination (`MoneroAddress` carries
  the payment ID) makes `monero-wallet` encrypt it into the tx extra — the
  payment ID flows to the recipient without changing the on-chain keys.

Implementation: `wallet::encode_integrated_address` / `integrated_payment_id`;
send path in the companion (`Address::from_str` preserves the payment ID).

### `xmr-output`

The companion tells the signer which on-chain one-time outputs are available to
spend, with the data needed to derive each one-time secret on-device.

```
request: xmr-output:<R_hex>;<index>:<P_hex>[:<major>:<minor>][;...]
```

- `<R_hex>` — the transaction public key (or per-output additional key), 32 bytes hex.
- `<index>` — the output's index within the transaction.
- `<P_hex>` — the one-time output public key, 32 bytes hex.
- `<major>:<minor>` — optional subaddress index the output was sent to.

Implementation: `keyimage::parse_output_payload`.

### `xmr-keyimage`

The signer returns the double-spend-proof key images for those outputs,
deriving the one-time secrets itself:

```
response: xmr-keyimage:<key_image_hex>[,<key_image_hex>...]
```

One entry per `xmr-output` entry, same order. The derivation (matches mainline
Monero and monero-wallet's audited scan path):

```
D      = 8·(a·R)
shared = H_s(D ‖ varint(index))
m      = H_s("SubAddr\0" ‖ a ‖ major_LE32 ‖ minor_LE32)      (subaddress only)
x      = spend + shared + m
assert x·G == P                                                ← ownership check
I      = x · H_p(P)     (H_p = ge_fromfe_frombytes_vartime, unknown dlog)
```

The `x·G == P` assertion is mandatory: a companion that claims an output this
wallet does not own gets an error, never a key image.

Implementation: `keyimage::compute_key_images_batch`.

### `xmr-txunsigned`

The companion presents an unsigned transaction for review + signing.

```
request: xmr-txunsigned:<hex>
```

The payload is an **encrypted and authenticated envelope** around monero-wallet's
native `SignableTransaction` serialization (inputs with decoys + commitments,
payments, fee rate — the actual object the signer will sign):

```
magic "xmxx-txunsigned-v2" ‖ version(1)
‖ dest_enc(XChaCha20-Poly1305) ‖ payload
‖ sig(64)   Schnorr over keccak256(dest_enc ‖ payload), view keypair
```

- `dest_enc` — the review summary `count ‖ (addr_len ‖ address ‖ amount)*`,
  **encrypted** with XChaCha20-Poly1305 keyed by
  `keccak256("xmxx-destinations-key" ‖ private_view_key)` (nonce derived the
  same way, AAD = the payload). This gives the recipient + amount
  **confidentiality** on the wire: a camera/observer reading the QR sees only
  ciphertext. Only the companion and the device (both hold the private view
  key) can read it.
- `payload` — `SignableTransaction::serialize()`.
- `sig` — Monero's Schnorr signature (`crypto.cpp generate_signature`), with a
  deterministic nonce so the device needs no RNG. Verifying it proves the data
  is unmodified **and** that the sender holds this wallet's view key — the
  "is this my wallet?" test (the same auth model as wallet2's unsigned_tx_set).
  Because the signature is over the *ciphertext*, tampering with either the
  encrypted destinations or the payload is caught by the signature (or the
  AEAD tag), whichever fires first.

Implementation: `txset::parse_unsigned_tx_set` (companion-side builder:
`txset::encode_unsigned_tx_set`).

### `xmr-txsigned`

The signer returns the signed transaction after CLSAG + Bulletproof+ signing
via monero-wallet's audited `SignableTransaction::sign`, deterministically
seeded (`ChaCha20Rng` from `keccak256(payload ‖ view_pub)`):

```
response: xmr-txsigned:<hex>
```

The hex is the serialized Monero `Transaction` — the companion only needs to
broadcast it.

Implementation: `txset::sign_tx`. It **cannot** report success without signing:
every input is ownership-verified (`(spend + key_offset)·G == P`), and any
failure is a hard error.

## Security invariants

- **Private keys never leave the signer.** Spend/view keys are derived and
  used on-device; only public keys, key images, and signatures cross the wire.
- **Key images are only emitted for owned outputs.** The `x·G == P` assertion
  is checked before anything is produced; a companion cannot make the signer
  commit to an output it does not own.
- **The unsigned set is authenticated.** A transaction not signed by this
  wallet's view key is rejected before any parsing — so a foreign or tampered
  set cannot reach the review screen.

- **The destinations are confidential.** The recipient + amount are
  XChaCha20-Poly1305-encrypted with a key derived from the private view key.
  Only the companion and the device can read them; the wire/QR carries
  ciphertext only.
- **What you review is what you sign.** The review shows the fee recomputed
  on-device from the actual object (`necessary_fee`), the payload fingerprint,
  and the authenticated destination summary. The destination *intent* is
  companion-asserted (only the companion knows the payment intent; the device
  has no way to recompute it from the serialized tx) — but it is bound to the
  signed payload by the envelope signature and the ownership checks, and the
  fingerprint lets a user cross-check against the companion.

## Honest gaps (documented, not hidden)

- **wallet2 binary interop is not implemented.** The wire format here is
  monero-wallet-native (which is what a signer server built on monero-oxide
  consumes). Importing a wallet2 `unsigned_tx_set` from Cake/Feather would
  require the CryptoNight-v0 key derivation (`cn_slow_hash_v0(view)`) and a
  portable_storage binary parser — a tracked follow-up, not silently claimed.
- **Signing integration is exercised end-to-end by the companion**, since
  constructing a `SignableTransaction` requires monero-wallet's scan/decoys
  flow. The signer side (parse → review → sign → serialize) is fully
  unit-tested here except for the final `sign()` call itself, which is a thin
  wrapper over monero-wallet's audited code.

## License

GPL-3.0-or-later, © 2026 OZARUMOTO.
