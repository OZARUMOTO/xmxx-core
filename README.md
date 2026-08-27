# xmxx-core 🟠

OZARUMOTO's **Monero reference crypto**, extracted from the `xmxx` KeyOS app so
it can back a Foundation **`monero-signer`** server — the same architecture as
Foundation's `bitcoin-signer` / `ethereum-signer`.

Pure crypto only. No UI, no transport, no device state. Built on
**monero-oxide / monero-wallet** (Luke Parker, Cypher Stack audit, May 2025),
so the risky primitives — CLSAG/Bulletproof+ signing, hash-to-point — are
vetted library code, not hand-rolled.

## Modules → signer-server messages

| Module | Message | Does |
|---|---|---|
| `wallet` | `xmr-address` | SLIP-0010 `m/44'/128'/account'` derivation, subaddresses, **25-word mnemonic export** |
| `keyimage` | `xmr-keyimage` | one-time key derivation + double-spend proofs, **ownership-asserted** |
| `txset` | `xmr-txunsigned` / `xmr-txsigned` | **authenticated** unsigned-set envelope, review, deterministic CLSAG signing |

See [`PROTOCOL.md`](PROTOCOL.md) for the exact `xmr-*` wire formats.

## What changed in 0.2.0 (why you can trust this now)

Review findings from the Foundation evaluation (issues #1–#3) are fixed
against primary sources — every derivation below was checked against
mainline Monero (`device_default.cpp`, `electrum-words.cpp`, `crypto.cpp`)
and the audited monero-wallet code, not memory.

| Finding | Fix |
|---|---|
| Keys were Ed25519-clamped, not reduced scalars; wallet unrecoverable elsewhere | `spend = sc_reduce32(SLIP-0010 key)`, `view = sc_reduce32(keccak256(spend))` — the Trezor/Ledger standard. **Restores in Feather/Cake/monero-wallet-cli**, and exports as a real 25-word Monero mnemonic (duplicate-checksum-word scheme, verified) |
| No subaddresses | `m = H_s("SubAddr\0" ‖ view_priv ‖ major_LE32 ‖ minor_LE32)`, `D = B + m·G`, `C = a·D` — byte-for-byte `device_default.cpp` |
| Key images derivable from public data (unsafe on-chain) | `I = x·H_p(P)` with `H_p = Point::biased_hash` (unknown dlog), **and `x·G == P` asserted before emitting** — a lying companion fails loudly |
| Wrong secret used for key images | one-time secret `x = H_s(8·a·R ‖ varint(index)) + b (+ m)` — the real Monero construction |
| `sign_tx` returned `Ok` with an empty signature | real CLSAG + Bulletproof+ signing via `SignableTransaction::sign`, deterministic (`ChaCha20Rng` from `keccak256(payload ‖ view_pub)`), every input ownership-verified, hard errors only |
| Review echoed companion JSON | review is device-derived where possible (`necessary_fee`, fingerprint) and the whole envelope is **Schnorr-authenticated with the view key** — foreign/tampered unsigned sets are rejected before parsing |
| `Debug` leaked keys, no Zeroize, `device` feature didn't compile, false `no_std` claim | keys are `Zeroizing`, manual `Debug` (address only), no device feature (the app calls `derive(&app_seed, account)`), std-only and honest about it |

## Why the base58 is still worth calling out

Monero block-wise base58 matches `monero/src/common/base58.cpp` exactly —
big-endian u64 blocks, right-aligned `1`-padding, and the characteristic
**`4`-prefix** — and `jpXCZedGfVQ` for `u64::MAX` is pinned as a test vector.

## Tests

```sh
cargo test        # 22 tests
```

Highlights: the **official SLIP-0010 ed25519 test vectors**; the Monero
`view == sc_reduce32(keccak256(spend))` invariant; subaddress construction
recomputed independently; mnemonic round-trip + tamper rejection + CRC-32
vector; key images computed for genuinely owned outputs and **rejected for
foreign/wrong outputs**; envelope round-trip, byte-tamper detection, and
foreign-wallet rejection.

## Honest gaps

- **wallet2 binary interop** (importing a Cake/Feather `unsigned_tx_set`) is
  not implemented — it needs the CryptoNight-v0 key derivation and a
  portable_storage parser. The wire format here is monero-wallet-native, which
  is what a signer server built on monero-oxide consumes.
- The final `SignableTransaction::sign()` call is exercised by the companion
  (constructing one requires monero-wallet's scan/decoys flow); the signer
  side is thin and unit-tested up to that call.

## Build

```sh
cargo build        # host, std
cargo test         # 22 unit tests
```

## License

GPL-3.0-or-later, © 2026 OZARUMOTO.

---

_Sideloaded on Passport Prime, syncing over the relay companion, built by
["OZARUMOTO"](https://github.com/OZARUMOTO)._
