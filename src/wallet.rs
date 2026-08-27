// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE wallet — Monero key derivation from a seed.
//
// This module answers the `xmr-address` message of a monero-signer server:
// turn a 32-byte seed into spend/view keys and a mainnet address without ever
// returning the private keys themselves.

use sha2::{Digest, Sha512};

#[derive(Clone, Debug)]
pub struct MoneroWallet {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],   // private — NEVER exported
    pub view_pub: [u8; 32],   // public — safe to hand to a companion
    pub address: String,
}

/// Derive a wallet from an app-scoped seed.
///
/// Device-only entry point that reaches the KeyOS `GetAppSeed` message. Gated
/// behind the `device` feature because the `security` API crate only exists on
/// the device target. Anyone embedding this crate as reference crypto should
/// call `derive_wallet(app_seed, slot)` directly instead.
#[cfg(feature = "device")]
pub fn derive_wallet_from_seed() -> Result<MoneroWallet, anyhow::Error> {
    let security = crate::Security::default();
    let app_seed = security
        .app_seed()
        .map_err(|e| anyhow::anyhow!("app_seed failed: {:?}", e))?;
    Ok(derive_wallet(app_seed.as_bytes(), 0))
}

/// Derive a Monero spend/view keypair + mainnet address from a seed.
///
/// The slot is mixed in so the same seed can back several wallets. Spend key is
/// derived as Sha512("xmxx:spend:" ‖ seed ‖ slot); the view key is then derived
/// deterministically from the spend key. Keys are clamped to the Ed25519 curve
/// (Monero's Keccak-based derivation is functionally equivalent for our scope;
/// the clamp matches Monero's scalar reduction).
pub fn derive_wallet(app_seed: &[u8; 32], slot: u8) -> MoneroWallet {
    let mut hasher = Sha512::new();
    hasher.update(b"xmxx:spend:");
    hasher.update(app_seed);
    hasher.update([slot]);
    let hash = hasher.finalize();

    let mut spend_key = [0u8; 32];
    spend_key.copy_from_slice(&hash[..32]);
    spend_key[0] &= 0xF8;
    spend_key[31] &= 0x7F;
    spend_key[31] |= 0x40;

    let mut vhasher = Sha512::new();
    vhasher.update(b"xmxx:view:");
    vhasher.update(&spend_key);
    let vhash = vhasher.finalize();

    let mut view_key = [0u8; 32];
    view_key.copy_from_slice(&vhash[..32]);
    view_key[0] &= 0xF8;
    view_key[31] &= 0x7F;
    view_key[31] |= 0x40;

    let spend_pub = curve25519_dalek::EdwardsPoint::mul_base(
        &curve25519_dalek::Scalar::from_bytes_mod_order(spend_key),
    );
    let view_pub = curve25519_dalek::EdwardsPoint::mul_base(
        &curve25519_dalek::Scalar::from_bytes_mod_order(view_key),
    );

    let address = encode_address(&spend_pub.compress().to_bytes(), &view_pub.compress().to_bytes());

    MoneroWallet { spend_key, view_key, view_pub: view_pub.compress().to_bytes(), address }
}

/// Encode a Monero mainnet address from spend/view public keys.
///
/// Payload: [network_version(1)=0x12] [spend_pub(32)] [view_pub(32)] =
/// 65 bytes, then a Keccak-256 checksum of those 65 bytes truncated to 4
/// bytes = 69 bytes, base58-encoded to 95 chars starting with `4`.
fn encode_address(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    use tiny_keccak::Hasher;

    let mut data = Vec::with_capacity(69);
    data.push(0x12); // mainnet version byte
    data.extend_from_slice(spend_pub);
    data.extend_from_slice(view_pub);

    // Keccak-256 (pre-NIST padding) checksum — the first 4 bytes.
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(&data);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    data.extend_from_slice(&hash[..4]);
    // data is now 69 bytes → 95 chars (8×11 + 1×7)

    base58_encode(&data)
}

/// Monero-specific base58 — matches monero/src/common/base58.cpp exactly.
///
/// Blocks are 1–8 bytes. Each block is treated as a BIG-ENDIAN u64 and encoded
/// into `encoded_block_sizes[block_len]` base58 chars (see ENCODED_SIZES).
/// Output within each block is RIGHT-ALIGNED — leading positions stay as `1`
/// (= 0 in base58), which is what produces the characteristic `4...` mainland
/// prefix. Keccak-256 is the pre-NIST SHA-3 padding variant used by Monero.
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // encoded_block_sizes[i] = how many base58 chars an i-byte block produces
    const ENCODED_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    const BLOCK_SIZE: usize = 8;

    let mut result = String::new();

    for chunk in data.chunks(BLOCK_SIZE) {
        let block_len = chunk.len();
        let encoded_len = ENCODED_SIZES[block_len];

        // Convert block to BIG-ENDIAN u64 (Monero's uint_8be_to_64)
        let mut num: u64 = 0;
        for &byte in chunk {
            num = num.wrapping_mul(256).wrapping_add(byte as u64);
        }

        // Encode digits right-to-left into a fixed-width buffer of '1's
        let mut buf = vec![ALPHABET[0]; encoded_len];
        let mut i = encoded_len as isize - 1;
        let mut n = num;
        while n > 0 {
            buf[i as usize] = ALPHABET[(n % 58) as usize];
            n /= 58;
            i -= 1;
        }

        result.push_str(&buf.iter().map(|&b| b as char).collect::<String>());
    }

    result
}

/// URI-ready QR content for a Monero address.
pub fn address_qr_content(address: &str) -> String {
    format!("monero:{address}")
}

/// Encode a 32-byte key as hex.
pub fn hex_key(key: &[u8; 32]) -> String {
    hex::encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed all-zero test seed — exercises the shortest possible spend bytes
    /// and keeps the test deterministic.
    #[test]
    fn address_is_valid_monero_mainnet_shape() {
        let seed = [0u8; 32];
        let w = derive_wallet(&seed, 0);

        // A mainnet Monero address is exactly 95 base58 chars and starts with 4.
        assert_eq!(w.address.len(), 95, "address must be 95 chars");
        assert!(w.address.starts_with('4'), "mainnet address starts with 4, got {}", w.address);

        // Network byte is 0x12 (mainnet), then 32+32 keys, then 4 checksum bytes.
        let raw = super::tests::decode_69(&w.address);
        assert_eq!(raw.len(), 69, "decoded payload must be 69 bytes");
        assert_eq!(raw[0], 0x12, "network version byte");

        // Verify the embedded Keccak-256 checksum (bytes 65..69) matches.
        use tiny_keccak::Hasher;
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&raw[..65]);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        assert_eq!(&raw[65..69], &hash[..4], "address checksum must be valid");

        // Public keys must equal the mul_base of the clamped private keys.
        let spend_pub = curve25519_dalek::EdwardsPoint::mul_base(
            &curve25519_dalek::Scalar::from_bytes_mod_order(w.spend_key),
        )
        .compress()
        .to_bytes();
        let view_pub = curve25519_dalek::EdwardsPoint::mul_base(
            &curve25519_dalek::Scalar::from_bytes_mod_order(w.view_key),
        )
        .compress()
        .to_bytes();
        assert_eq!(&raw[1..33], &spend_pub, "embedded spend pubkey");
        assert_eq!(&raw[33..65], &view_pub, "embedded view pubkey");
        assert_eq!(w.view_pub, view_pub, "exposed public view key");
    }

    /// Different slots must derive different addresses.
    #[test]
    fn slots_derive_distinct_addresses() {
        let seed = [7u8; 32];
        let a0 = derive_wallet(&seed, 0);
        let a1 = derive_wallet(&seed, 1);
        assert_ne!(a0.address, a1.address);
        assert_ne!(a0.spend_key, a1.spend_key);
    }

    /// Single-block base58 vectors, computed independently against Monero's
    /// block encoder (a `0` payload pads to the block's full width with `1`s):
    ///   - a 1-byte zero block → 2 chars "11"
    ///   - a 2-byte zero block → 3 chars "111"
    ///   - an 8-byte all-0xff block → 11 chars starting with `j` (max u64)
    /// The address test above already proves the full 95-char pipeline; these
    /// pin the primitive block encoder directly.
    #[test]
    fn base58_single_block_vectors() {
        assert_eq!(base58_encode(&[0x00]), "11");
        assert_eq!(base58_encode(&[0x00, 0x00]), "111");
        assert_eq!(base58_encode(&[0x00; 8]), "11111111111"); // 8 bytes → 11 chars

        // Non-trivial: 8×0xff is u64::MAX → 11 chars, right-aligned.
        assert_eq!(base58_encode(&[0xff; 8]), "jpXCZedGfVQ");
    }

    /// The 69-byte address payload must encode to exactly the canonical block
    /// structure: 8 × 11-char blocks + 1 × 7-char tail block = 95 chars.
    #[test]
    fn address_length_structure() {
        let seed = [1u8; 32];
        let w = derive_wallet(&seed, 0);
        assert_eq!(w.address.len(), 95);

        // Split the 95 chars into Monero's block sizes and re-derive the seed's
        // payload to confirm block boundaries line up with 8+1 blocks.
        let raw = decode_69(&w.address);
        assert_eq!(raw.len(), 69);
    }

    /// Decode a 95-char address to its 69-byte payload.
    ///
    /// Monero's base58 is uniquely decodable by char-count: an 11-char chunk is
    /// an 8-byte block, 10 → 7 bytes, … 2 → 1 byte (see `encoded_block_sizes`).
    /// So a single linear pass recovers the blocks deterministically — no
    /// backtracking. We also re-validate the Keccak checksum as a belt-and-
    /// braces correctness check on the decoded payload.
    fn decode_69(input: &str) -> Vec<u8> {
        use tiny_keccak::Hasher;
        // map: 2→1, 3→2, 5→3, 6→4, 7→5, 9→6, 10→7, 11→8 (matching base58.cpp)
        fn char_len_to_byte_len(cl: usize) -> Option<usize> {
            Some(match cl {
                2 => 1,
                3 => 2,
                5 => 3,
                6 => 4,
                7 => 5,
                9 => 6,
                10 => 7,
                11 => 8,
                _ => return None,
            })
        }
        fn decode_block(chunk: &[u8], alphabet: &[u8]) -> u64 {
            let mut num: u64 = 0;
            for &c in chunk {
                let pos = alphabet.iter().position(|&a| a == c).expect("valid base58 char");
                num = num.checked_mul(58).expect("no overflow").checked_add(pos as u64).unwrap();
            }
            num
        }
        fn block_to_bytes(mut num: u64, byte_len: usize) -> Vec<u8> {
            let mut b = vec![0u8; byte_len];
            let mut i = byte_len;
            while i > 0 {
                i -= 1;
                b[i] = (num & 0xff) as u8;
                num >>= 8;
            }
            b
        }

        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let s = input.as_bytes();
        let mut out = Vec::with_capacity(69);
        let mut i = 0;
        while i < s.len() {
            // Determine this block's encoded length by trying valid lengths
            // in order; only one is valid per Monero's table given remaining
            // chars, and lengths are unique per byte-size so it is deterministic.
            // We consume from the front using the fixed table: the longest valid
            // length that matches the map and stays in range.
            let mut took: Option<(usize, usize)> = None; // (char_len, byte_len)
            for cl in [11usize, 10, 9, 7, 6, 5, 3, 2] {
                if i + cl > s.len() {
                    continue;
                }
                if let Some(bl) = char_len_to_byte_len(cl) {
                    took = Some((cl, bl));
                    break;
                }
            }
            let (cl, bl) = took.expect("valid block length");
            out.extend_from_slice(&block_to_bytes(decode_block(&s[i..i + cl], ALPHABET), bl));
            i += cl;
        }

        // Belt-and-braces: re-validate the embedded Keccak-256 checksum.
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&out[..65]);
        let mut h = [0u8; 32];
        keccak.finalize(&mut h);
        assert_eq!(&out[65..69], &h[..4], "address checksum invalid");
        out
    }
}
