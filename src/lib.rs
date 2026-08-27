// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE — OZARUMOTO's Monero reference crypto.
//
// Extracted from the xmxx KeyOS app so it can back a foundation `monero-signer`
// server. Pure crypto only: key derivation, key images, and the unsigned/signed
// tx wire formats. No UI, no transport, no device state.
//
// The three modules map 1:1 onto a signer-server message surface:
//   * `wallet`    → xmr-address   (seed → spend/view + verified Monero base58)
//   * `keyimage`  → xmr-keyimage  (hash-to-point + double-spend-proof computation)
//   * `txset`     → xmr-txunsigned / xmr-txsigned (wire format + review fields)
//
// Compile on any host with `cargo build`. The only device-coupled entry point,
// `wallet::derive_wallet_from_seed`, is gated behind the `device` feature and
// only builds against the KeyOS `security` crate.
pub mod wallet;
pub mod keyimage;
pub mod txset;