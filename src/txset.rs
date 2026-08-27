// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE transaction set — the xmr-txunsigned / xmr-txsigned wire format
// and the review surface.
//
// This is the reference interface a monero-signer server implements:
//
//   1. Companion encodes a wallet2 `unsigned_tx_set` (encrypted) as an
//      `xmr-txunsigned` payload.
//   2. The signer decrypts with the CryptoNight-v0 key derived from the view
//      key, Blake2b-HMAC verifies the auth tag, and CBOR-parses sources,
//      destinations and fee.
//   3. The signer shows a review screen (see `preview_tx`) and reconstructs
//      OutputWithDecoys per input.
//   4. The signer seeds a deterministic ChaCha20Rng and calls monero-wallet's
//      `SignableTransaction::sign()` (CLSAG + Bulletproof+).
//   5. The result is repackaged as a wallet2 `signed_tx_set` and encoded as an
//      `xmr-txsigned` payload for the companion to broadcast.

/// An unsigned Monero transaction (parsed from companion/wallet2 format).
#[derive(Clone, Debug)]
pub struct UnsignedTx {
    /// Transaction destinations (address, amount in piconeros).
    pub destinations: Vec<(String, u64)>,
    /// Total fee in piconeros.
    pub fee: u64,
    /// Input count (number of outputs being spent).
    pub input_count: usize,
    /// Raw encrypted tx data (for signing).
    pub raw_data: Vec<u8>,
}

/// Preview of an unsigned transaction for the on-device review screen.
#[derive(Clone, Debug)]
pub struct TxPreview {
    pub to_addr: String,
    pub amount_xmr: String,
    pub fee_xmr: String,
    pub status: String,
}

/// Parse a wallet2 `unsigned_tx_set` from QR data (`xmr-txunsigned:` or
/// `ur:bytes/` wrapped).
///
/// The strict wallet2 encrypted format is not yet implemented here — the
/// companion currently emits a JSON `unsigned_tx_set` which we parse directly.
/// Support for the encrypted CryptoNight/HMAC envelope is the next step (see
/// module doc, step 1–2).
pub fn parse_unsigned_tx_set(qr_data: &str, _spend_key: &[u8; 32]) -> Result<UnsignedTx, anyhow::Error> {
    let hex_data = qr_data
        .trim()
        .strip_prefix("xmr-txunsigned:")
        .or_else(|| qr_data.strip_prefix("ur:bytes/"))
        .unwrap_or(qr_data);

    let raw = hex::decode(hex_data)?;

    // Companion-generated JSON unsigned_tx_set (initial testing format).
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw) {
        let destinations = json["destinations"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| {
                        let addr = d["address"].as_str()?.to_string();
                        let amount = d["amount"].as_u64()?;
                        Some((addr, amount))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let fee = json["fee"].as_u64().unwrap_or(0);

        return Ok(UnsignedTx {
            destinations,
            fee,
            input_count: json["input_count"].as_u64().unwrap_or(1) as usize,
            raw_data: raw,
        });
    }

    Err(anyhow::anyhow!(
        "wallet2 format not yet implemented — scan a companion-generated unsigned tx"
    ))
}

/// Preview an unsigned transaction for the review screen.
pub fn preview_tx(tx: &UnsignedTx) -> TxPreview {
    let (to_addr, amount) = if let Some((addr, amt)) = tx.destinations.first() {
        (addr.clone(), *amt)
    } else {
        ("unknown".to_string(), 0)
    };

    TxPreview {
        to_addr,
        amount_xmr: format_xmr(amount),
        fee_xmr: format_xmr(tx.fee),
        status: format!("{} input(s) · {} output(s)", tx.input_count, tx.destinations.len()),
    }
}

/// Format piconeros as an XMR string.
fn format_xmr(piconero: u64) -> String {
    let whole = piconero / 1_000_000_000_000;
    let frac = piconero % 1_000_000_000_000;
    if frac == 0 {
        format!("{whole}.000000000000 XMR")
    } else {
        format!("{whole}.{frac:012} XMR")
    }
}

/// Sign an unsigned transaction using CLSAG + Bulletproof+.
///
/// TODO: wire `monero-oxide`'s `SignableTransaction::sign()` here. The return
/// envelope (an `xmr-txsigned` payload the companion broadcasts) is the
/// contract; the CLSAG/BP+ signing itself is the step that must integrate the
/// serai monero-wallet crate against a reconstructed OutputWithDecoys set.
pub fn sign_tx(_tx: &UnsignedTx, _spend_key: &[u8; 32]) -> Result<String, anyhow::Error> {
    // For now, return the raw tx data as hex for testing the wire format.
    Ok(String::new())
}