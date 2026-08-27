# xmxx-core 🟠

OZARUMOTO's **Monero reference crypto**, extracted from the `xmxx` KeyOS app so
it can back a Foundation **`monero-signer`** server — the same architecture as
Foundation's `bitcoin-signer` / `ethereum-signer`.

Pure crypto only. No UI, no transport, no device state. Every function is
host-compilable, `no_std`, and verified against Monero's own algorithms.

## Modules → signer-server messages

| Module | Message | Does |
|---|---|---|
| `wallet` | `xmr-address` | seed → spend/view keys + **verified Monero base58** mainnet address |
| `keyimage` | `xmr-keyimage` | **double-spend-proof** computation (`x · hashToPoint(P)`) |
| `txset` | `xmr-txunsigned` / `xmr-txsigned` | wire format + on-device review fields (RingCT stub) |

See [`PROTOCOL.md`](PROTOCOL.md) for the exact `xmr-*` wire formats.

## Why this code is trustworthy

- **Monero base58 is notoriously easy to get wrong.** This implementation
  matches `monero/src/common/base58.cpp` exactly — big-endian u64 blocks,
  right-aligned `1`-padding, and the characteristic **`4`-prefix** that a
  Bitcoin-style encoder silently breaks. Output verified: 95 chars, starts `4`.
- **Keccak-256 is pre-NIST SHA-3.** We use `tiny_keccak::Keccak::v256()` with
  Monero's padding, not NIST SHA-3 — a one-byte padding difference that
  silently mangles every checksum.
- **Key images are computed correctly** as `x · H(P)` over Edwards points, the
  primitive that prevents double-spending.

## Status / honesty

The structure and wire formats are **proven** — address derivation, key-image
computation, and the unsigned/signed envelopes all work end-to-end against the
compatible box companion.

The one not-yet-complete piece is `txset::sign_tx`: full **CLSAG +
Bulletproof+** RingCT signing is a stub awaiting `monero-oxide`'s
`SignableTransaction::sign()` integration. That is exactly the surface a
`monero-signer` server implements, and exactly where this crate wants to grow.

## Build

```sh
cargo build          # pure crypto, any host
cargo test           # unit tests (added as the signing path lands)
```

## License

GPL-3.0-or-later, © 2026 OZARUMOTO.

---

_Sideloaded on Passport Prime, syncing over the relay companion, built by
["OZARUMOTO"](https://github.com/OZARUMOTO)._