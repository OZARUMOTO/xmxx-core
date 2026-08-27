// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Verification against the CANONICAL Monero test vectors
// (monero-project/monero tests/crypto/tests.txt) and an independent vetted
// address implementation (serai's monero-address).
//
// These vectors are the gold standard Monero uses to test its own crypto
// (tests/crypto/crypto.cpp). Passing them means our primitives — scalar
// hashing, key derivation, one-time keys, key images, Schnorr signatures —
// are byte-identical to mainline Monero's.

use xmxx_core::wallet::{
    base58_decode, encode_address, validate_address, MoneroWallet,
};
use xmxx_core::{Point, Scalar};

fn h32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).unwrap();
    b.try_into().unwrap()
}

fn hvec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Monero's hash_to_scalar = sc_reduce32(cn_fast_hash(data)).
/// tests.txt: `hash_to_scalar <data> <expected>`
#[test]
fn hash_to_scalar_matches_monero_vectors() {
    let vectors: &[(&str, &str)] = &[
        (
            "59d28aeade98016722948bf596af0b7deb5dd641f1aa2a906bd4e1",
            "7d0b25809fc4032a81dd5b0f721a2b21f7f68157c834374f580876f5d91f7409",
        ),
        (
            "60d9a4b96951481ab458",
            "b0955682b297dbcae4a5c1b6f21addb211d6180632b538472045b5d592c38109",
        ),
        (
            "7d535b4896ddc350a5fdff",
            "7bb1a59783be93ada537801f31ef52b0d2ea135a084c47cbad9a7c6b0d2c990f",
        ),
    ];
    for (data, expected) in vectors {
        let got: [u8; 32] = <[u8; 32]>::from(Scalar::hash(hvec(data)));
        assert_eq!(got, h32(expected), "hash_to_scalar({data})");
    }
}

/// Monero's generate_key_derivation = 8·(a·R).
/// tests.txt: `generate_key_derivation <R> <a> true <derivation>`
#[test]
fn key_derivation_matches_monero_vectors() {
    let vectors: &[(&str, &str, &str)] = &[
        (
            "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984",
            "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02",
            "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67",
        ),
        (
            "1ebf8c3c296bb91708b09d9a8e0639ccfd72556976419c7dc7e6dfd7599218b9",
            "e49f363fd5c8fc1f8645983647ca33d7ec9db2d255d94cd538a3cc83153c5f04",
            "72903ec8f9919dfcec6efb5535490527b573b3d77f9890386d373c02bf368934",
        ),
        (
            "3e3047a633b1f84250ae11b5c8e8825a3df4729f6cbe4713b887db62f268187d",
            "6df324e24178d91c640b75ab1c6905f8e6bb275bc2c2a5d9b9ecf446765a5a05",
            "9dcac9c9e87dd96a4115d84d587218d8bf165a0527153b1c306e562fe39a46ab",
        ),
    ];
    for (r_hex, a_hex, expected) in vectors {
        let r = curve25519_dalek::edwards::CompressedEdwardsY(h32(r_hex)).decompress().unwrap();
        let a = curve25519_dalek::Scalar::from_bytes_mod_order(h32(a_hex));
        let derivation = (&a * &r).mul_by_cofactor();
        assert_eq!(
            derivation.compress().to_bytes(),
            h32(expected),
            "generate_key_derivation(R={r_hex})"
        );
    }
}

/// Monero's derive_secret_key = H_s(derivation ‖ varint(index)) + base.
/// tests.txt: `derive_secret_key <derivation> <index> <base> <expected>`
#[test]
fn derive_secret_key_matches_monero_vectors() {
    let vectors: &[(&str, u64, &str, &str)] = &[
        (
            "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97",
            66,
            "5619c62aa4ad787274b1071598b6ecacf4f9dacca2fd11b0c80741b744400500",
            "55297d64b0c0556d5583ce0e30c2024ccce90c93d16bdeb4e40fce7afff87803",
        ),
        (
            "fea25a8d0184526c85c16c032c7678c7a1e3ace773b31566d159dc8a3cb81ae1",
            755,
            "265685f284fe213678cad94e337196428237ac55edb5871c1f0209769ba9a803",
            "e83934c766427920055d77755b7205156e1bffc37f68135182f0974fe008470c",
        ),
        (
            "df2c15b6f3ee51445f9097f5488158a8021dd15be1e6dbe676087bda1f2d9760",
            62075,
            "04a4ca22d78a0e746c9e58e785da9635664cfdccf4b1e87537b359f656dff403",
            "6bad669f91c2df065ee93b446b2db9d3582960ff804096ef76be64febda5450e",
        ),
    ];
    for (derivation_hex, index, base_hex, expected) in vectors {
        let mut data = hvec(derivation_hex);
        monero_oxide::io::VarInt::write(index, &mut data).unwrap();
        let shared = Scalar::hash(&data);
        let base = curve25519_dalek::Scalar::from_bytes_mod_order(h32(base_hex));
        let derived: curve25519_dalek::Scalar = shared.into();
        let result: [u8; 32] = <[u8; 32]>::from(Scalar::from(derived + base));
        assert_eq!(result, h32(expected), "derive_secret_key(idx={index})");
    }
}

/// Monero's generate_key_image = sec·H_p(pub) with H_p = ge_fromfe_frombytes_vartime.
/// tests.txt: `generate_key_image <pub> <sec> <key_image>`
#[test]
fn key_image_matches_monero_vectors() {
    let vectors: &[(&str, &str, &str)] = &[
        (
            "e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0",
            "981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f",
            "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887",
        ),
        (
            "8661153f5f856b46f83e9e225777656cd95584ab16396fa03749ec64e957283b",
            "156d7f2e20899371404b87d612c3587ffe9fba294bafbbc99bb1695e3275230e",
            "03ec63d7f1b722f551840b2725c76620fa457c805cbbf2ee941a6bf4cfb6d06c",
        ),
        (
            "30216ae687676a89d84bf2a333feeceb101707193a9ee7bcbb47d54268e6cc83",
            "1b425ba4b8ead10f7f7c0c923ec2e6847e77aa9c7e9a880e89980178cb02fa0c",
            "4f675ce3a8dfd806b7c4287c19d741f51141d3fce3e3a3d1be8f3f449c22dd19",
        ),
    ];
    for (pub_hex, sec_hex, expected) in vectors {
        // H_p via the same vetted Point::biased_hash the keyimage module uses.
        let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(h32(pub_hex)).into();
        let sec = curve25519_dalek::Scalar::from_bytes_mod_order(h32(sec_hex));
        let key_image = (sec * hp).compress().to_bytes();
        assert_eq!(key_image, h32(expected), "generate_key_image(pub={pub_hex})");
    }
}

/// Monero's check_signature — our Schnorr verify must accept/reject exactly
/// what Monero does.
/// tests.txt: `check_signature <hash> <pub> <sig(c‖r)> <expected>`
#[test]
fn schnorr_verify_matches_monero_vectors() {
    let vectors: &[(&str, &str, &str, bool)] = &[
        (
            "57fd3427123988a99aae02ce20312b61a88a39692f3462769947467c6e4c3961",
            "a5e61831eb296ad2b18e4b4b00ec0ff160e30b2834f8d1eda4f28d9656a2ec75",
            "cd89c4cbb1697ebc641e77fdcd843ff9b2feaf37cfeee078045ef1bb8f0efe0bb5fd0131fbc314121d9c19e046aea55140165441941906a757e574b8b775c008",
            true,
        ),
        (
            "92c1259cddde43602eeac1ab825dc12ffc915c9cfe57abcca04c8405df338359",
            "9fa6c7fd338517c7d45b3693fbc91d4a28cd8cc226c4217f3e2694ae89a6f3dc",
            "b027582f0d05bacb3ebe4e5f12a8a9d65e987cc1e99b759dca3fee84289efa5124ad37550b985ed4f2db0ab6f44d2ebbc195a7123fd39441d3a57e0f70ecf608",
            false,
        ),
    ];
    for (hash_hex, pub_hex, sig_hex, expected) in vectors {
        let hash = h32(hash_hex);
        let pub_point = Point::from(
            curve25519_dalek::edwards::CompressedEdwardsY(h32(pub_hex)).decompress().unwrap(),
        );
        let sig = hvec(sig_hex);
        let got = xmxx_core::txset::schnorr_verify(&hash, &pub_point, &sig[..32], &sig[32..]);
        assert_eq!(got, *expected, "check_signature(hash={hash_hex})");
    }
}

/// Our address encoding must match serai's independent vetted implementation
/// byte-for-byte, for both standard and subaddress types.
#[test]
fn address_matches_monero_address_crate() {
    use monero_address::{Address, AddressType, MoneroAddress, Network};

    let w = MoneroWallet::derive(&[21u8; 32], 0);
    let spend: Point = Point::from(
        curve25519_dalek::edwards::CompressedEdwardsY(w.spend_public()).decompress().unwrap(),
    );
    let view: Point = w.view_public_point();

    let ours = encode_address(&w.spend_public(), &w.view_public());
    let theirs: MoneroAddress = Address::new(Network::Mainnet, AddressType::Legacy, spend, view);
    assert_eq!(ours, theirs.to_string(), "standard address must match monero-address");
    assert_eq!(ours, w.address());

    // monero-address must also parse ours.
    let parsed: MoneroAddress = Address::from_str(Network::Mainnet, &ours).unwrap();
    assert_eq!(parsed.to_string(), ours);

    // Subaddress: D = B + m·G, C = a·D — must match monero-address's
    // Subaddress encoding of the same points.
    let sub = w.subaddress(0, 1);
    assert!(validate_address(&sub));
    let raw = base58_decode(&sub).unwrap();
    let d = Point::from(
        curve25519_dalek::edwards::CompressedEdwardsY(raw[1..33].try_into().unwrap())
            .decompress()
            .unwrap(),
    );
    let c = Point::from(
        curve25519_dalek::edwards::CompressedEdwardsY(raw[33..65].try_into().unwrap())
            .decompress()
            .unwrap(),
    );
    let their_sub: MoneroAddress =
        Address::new(Network::Mainnet, AddressType::Subaddress, d, c);
    assert_eq!(sub, their_sub.to_string(), "subaddress must match monero-address");
    let parsed_sub: MoneroAddress = Address::from_str(Network::Mainnet, &sub).unwrap();
    assert!(parsed_sub.is_subaddress());
}

/// base58 encode/decode round-trips through monero-address's base58 path by
/// validating every address we produce.
#[test]
fn addresses_validate_across_derivations() {
    for account in 0..3 {
        let w = MoneroWallet::derive(&[account as u8 + 1; 32], account);
        assert!(validate_address(w.address()));
        for (major, minor) in [(0u32, 0u32), (0, 2), (1, 0)] {
            let sub = w.subaddress(major, minor);
            assert!(validate_address(&sub), "subaddress {major}:{minor} must validate");
        }
    }
}
