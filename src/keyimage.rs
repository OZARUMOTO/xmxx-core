// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE key images — the double-spend-proof computation.
//
// Answers the `xmr-keyimage` message of a monero-signer server. Key images are
// what prevent double-spending: each on-chain output you own is hashed to a
// curve point and multiplied by your spend key, producing a value only the
// owner can compute, that is checked once per chain.

use sha2::{Digest, Sha512};

/// Compute the key image for a single output.
///
/// `spend_key` is the private spend key; `output_pub_key` is the output's
/// one-time public key as it appears on-chain. The result is a 32-byte key
/// image that accompanies a spend of that output.
pub fn compute_key_image(spend_key: &[u8; 32], output_pub_key: &[u8; 32]) -> [u8; 32] {
    let hp = hash_to_point(output_pub_key);
    let s = curve25519_dalek::Scalar::from_bytes_mod_order(*spend_key);

    // Hp = hashToPoint(P); key_image = x * Hp, where x is the spend key.
    let p = curve25519_dalek::EdwardsPoint::mul_base(
        &curve25519_dalek::Scalar::from_bytes_mod_order(hp),
    );
    (s * p).compress().to_bytes()
}

/// Hash a public key to an Edwards-curve point (Monero's hashToPoint).
///
/// Sha512 the key, reduce the first 32 bytes to a scalar, and multiply by the
/// basepoint. This is the same primitive Monero uses for key-image derivation.
fn hash_to_point(pub_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(pub_key);
    let hash = hasher.finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    let point = curve25519_dalek::EdwardsPoint::mul_base(
        &curve25519_dalek::Scalar::from_bytes_mod_order(scalar_bytes),
    );
    point.compress().to_bytes()
}

/// Compute key images for a batch of owned outputs.
pub fn compute_key_images_batch(spend_key: &[u8; 32], outputs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    outputs.iter().map(|pub_key| compute_key_image(spend_key, pub_key)).collect()
}

/// Parse an `xmr-output` QR payload: a comma-separated list of 32-byte hex
/// output keys from a companion's chain scan.
pub fn parse_output_payload(data: &str) -> Result<Vec<[u8; 32]>, anyhow::Error> {
    let data = data.trim();
    let data = data.strip_prefix("xmr-output:").unwrap_or(data);
    let hex_strs: Vec<&str> = data.split(',').collect();

    let mut outputs = Vec::with_capacity(hex_strs.len());
    for hex_str in hex_strs {
        let bytes = hex::decode(hex_str.trim())?;
        if bytes.len() != 32 {
            anyhow::bail!("output key must be 32 bytes, got {}", bytes.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        outputs.push(key);
    }
    Ok(outputs)
}

/// Encode key images as an `xmr-keyimage` QR payload for the companion.
pub fn encode_keyimage_payload(key_images: &[[u8; 32]]) -> String {
    let hex_strs: Vec<String> = key_images.iter().map(|ki| hex::encode(ki)).collect();
    format!("xmr-keyimage:{}", hex_strs.join(","))
}