# XMXX-CORE wire protocol

Reference wire formats for a Foundation `monero-signer` server, extracted from
the OZARUMOTO `xmxx` KeyOS app. All payloads are short, hard-provable text
strings meant to survive QR encoding (animated UR or static), USB vendor
transport, or the QLv2 relay.

## Messages

### `xmr-address`

Derive a Monero address (optionally a subaddress) from a seed. Never returns
private keys.

```
request:  xmr-address:<slot>
response: monero:<address>          # e.g. monero:49B1re7YK...ZJ1Ad
```

- `<slot>` — an integer wallet slot under the seed.
- `<address>` — 95-char mainnet address (starts with `4`).

Implementation: `wallet::derive_wallet(seed, slot)` → `MoneroWallet.address`.
Base58 encoding matches `monero/src/common/base58.cpp` exactly.

### `xmr-output`

The companion tells the signer which on-chain one-time output public keys are
available to be spent. This is the *input* to key-image computation.

```
request:  xmr-output:<output_key_hex>[,<output_key_hex>...]
```

- Each `<output_key_hex>` is 32 bytes hex (64 chars) — a one-time output pubkey.

Implementation: `keyimage::parse_output_payload`.

### `xmr-keyimage`

The signer returns the computed key images for those outputs (the
double-spend-proof). The companion records them so it can correlate which
outputs are unspent.

```
response: xmr-keyimage:<key_image_hex>[,<key_image_hex>...]
```

- One entry per `xmr-output` entry, same order.
- Each `<key_image_hex>` is 32 bytes hex — `x · hashToPoint(P)`.

Implementation: `keyimage::compute_key_images_batch`.

### `xmr-txunsigned`

The companion presents an unsigned transaction for review + signing. Carries a
wallet2 `unsigned_tx_set` plus the derived crypto material the signer needs to
authenticate it.

```
request:  xmr-txunsigned:<hex>     # raw bytes (JSON now; wallet2 encrypted later)
```

The full wallet2 path (module doc steps 1–2) is:
1. Decrypt with the CryptoNight-v0 key derived from the view key.
2. Blake2b-HMAC verify the auth tag.
3. CBOR-parse sources, destinations, fee.

Today the companion emits a JSON `unsigned_tx_set`:

```json
{
  "destinations": [{"address": "4...", "amount": 120000000000}],
  "fee": 24000000000,
  "input_count": 1
}
```

Implementation: `txset::parse_unsigned_tx_set`.

### `xmr-txsigned`

The signer returns the signed transaction after CLSAG + Bulletproof+ signing,
repackaged as a wallet2 `signed_tx_set` for the companion to broadcast.

```
response: xmr-txsigned:<hex>
```

Implementation: `txset::sign_tx` (stub — CLSAG/BP+ signing still to be wired
through `monero-oxide`).

## Security invariants

- **Private keys never leave the signer.** `spend_key` / `view_key` are derived
  and used entirely on-device; only the public keys and computed key images /
  signatures cross the wire.
- **Key images are authoritative.** The companion can combine `xmr-output` +
  `xmr-keyimage` to know which outputs are owned and unspent, but cannot spend.
- **The spend path requires the seed's signature.** `sign_tx` runs inside the
  signer against the device/app seed; the companion can only broadcast the
  returned `xmr-txsigned` bytes.

## License

GPL-3.0-or-later, © 2026 OZARUMOTO.