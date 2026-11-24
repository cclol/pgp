use base64::engine::{general_purpose::STANDARD as B64, Engine as _};
use pgp::types::StringToKey;

use crate::crypto::{
    decrypt_message, encrypt_message, generate_key, import_keys, sign_detached, verify_detached,
    DecryptRequest, EncryptRequest, ImportKeyRequest, KeyGenRequest, SignDetachedRequest,
    VerifyDetachedRequest,
};
use crate::limits::{check_s2k_string_to_key, MAX_INPUT_BYTES};
use crate::packet_check::armor_has_forbidden_headers;
use crate::session::SessionStore;

const TEST_NOW: u32 = 1_760_000_000;

fn gen_test_key(store: &mut SessionStore, uid: Option<&str>, pw: &str) -> crate::crypto::KeyGenResponse {
    generate_key(
        store,
        KeyGenRequest {
            user_id: uid.map(String::from),
            passphrase: pw.to_string(),
            profile: Some("modern".into()),
            now_secs: TEST_NOW,
        },
    )
    .expect("keygen should succeed")
}

#[test]
fn test_keygen_v6_passphrase_and_armor_headers() {
    let mut store = SessionStore::default();

    // Reject empty / short passphrase
    let err = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: Some("pseudonym".into()),
            passphrase: "short".into(),
            profile: None,
            now_secs: TEST_NOW,
        },
    );
    assert!(err.is_err());

    // Pseudonymous / empty UID supported on v6 (default profile when profile is None)
    let kp = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: None,
            passphrase: "correct-horse-battery-staple".into(),
            profile: None,
            now_secs: TEST_NOW,
        },
    )
    .expect("default modern keygen should succeed");
    assert_eq!(kp.summary.version, "V6");
    assert_eq!(kp.summary.algorithm, "Ed25519");
    assert!(kp.summary.has_secret);
    assert!(kp.summary.can_encrypt);
    assert!(kp.summary.can_sign);
    assert!(!armor_has_forbidden_headers(&kp.public_key_armored));
    assert!(!armor_has_forbidden_headers(&kp.secret_key_armored));
    assert!(!kp.public_key_armored.contains("Version:"));
    assert!(!kp.public_key_armored.contains("Comment:"));
    assert!(!kp.secret_key_armored.contains("Version:"));
    assert!(!kp.secret_key_armored.contains("Comment:"));
}

#[test]
fn test_rfc9580_multi_recipient_encrypt_audit_and_decrypt() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice-pseudo"), "alice-passphrase-1234");
    let bob = gen_test_key(&mut store, Some("bob-pseudo"), "bob-passphrase-5678");

    let secret_msg = b"Zero-Trace RFC 9580 payload with \x00 binary bytes!";
    let enc = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(secret_msg),
            recipient_fingerprints: vec![
                alice.summary.fingerprint.clone(),
                bob.summary.fingerprint.clone(),
            ],
            sign_fingerprint: Some(alice.summary.fingerprint.clone()),
            sign_passphrase: Some("alice-passphrase-1234".into()),
            profile: Some("rfc9580".into()),
            armor: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("encrypt should succeed");

    // Direct packet-level audit assertions
    assert_eq!(enc.packet_audit.pkesk_count, 2);
    assert!(enc.packet_audit.all_pkesk_anonymous);
    assert_eq!(enc.packet_audit.pkesk_versions, vec![6, 6]);
    assert_eq!(enc.packet_audit.seipd_version, Some(2));
    assert!(!enc.packet_audit.has_unauthenticated_sed);
    assert!(!enc.packet_audit.armor_has_version_or_comment);
    let armored = enc.output_armored.as_ref().expect("armored output");
    assert!(!armored.contains("Version:"));
    assert!(!armored.contains("Comment:"));

    // Import only Bob's secret key + Alice's public key in a fresh session
    let mut bob_store = SessionStore::default();
    import_keys(
        &mut bob_store,
        ImportKeyRequest {
            data_b64: B64.encode(bob.secret_key_armored.as_bytes()),
        },
    )
    .expect("import bob secret");
    import_keys(
        &mut bob_store,
        ImportKeyRequest {
            data_b64: B64.encode(alice.public_key_armored.as_bytes()),
        },
    )
    .expect("import alice public");

    let dec = decrypt_message(
        &bob_store,
        DecryptRequest {
            input_b64: enc.output_b64.clone(),
            passphrase: Some("bob-passphrase-5678".into()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("bob should decrypt");

    assert_eq!(B64.decode(&dec.plaintext_b64).unwrap(), secret_msg);
    assert_eq!(dec.seipd_version, 2);
    assert_eq!(dec.literal_filename, "");
    assert_eq!(dec.literal_timestamp, 0);
    // Signature status, fingerprint, and user-confirmed identity are separated!
    assert_eq!(dec.signature.status, "valid");
    assert_eq!(
        dec.signature.signer_fingerprint.as_deref(),
        Some(alice.summary.fingerprint.as_str())
    );
    assert!(!dec.signature.signer_identity_confirmed);

    // After explicit out-of-band confirmation, identity_confirmed becomes true
    bob_store
        .confirm_identity(&alice.summary.fingerprint, true)
        .expect("confirm identity");
    let dec2 = decrypt_message(
        &bob_store,
        DecryptRequest {
            input_b64: enc.output_b64,
            passphrase: Some("bob-passphrase-5678".into()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("bob decrypt 2");
    assert!(dec2.signature.signer_identity_confirmed);
}

#[test]
fn test_compat_seipd_v1_explicit_read_profile() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice"), "alice-passphrase-1234");

    let enc = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(b"Legacy v1 SEIPD test"),
            recipient_fingerprints: vec![alice.summary.fingerprint.clone()],
            sign_fingerprint: None,
            sign_passphrase: None,
            profile: Some("compat_seipd_v1".into()),
            armor: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("compat v1 encrypt");

    assert_eq!(enc.packet_audit.seipd_version, Some(1));
    assert_eq!(enc.packet_audit.pkesk_versions, vec![3]);
    assert!(enc.packet_audit.all_pkesk_anonymous);

    // Rejected when allow_legacy_seipd_v1 is false
    let err = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: enc.output_b64.clone(),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    );
    assert!(err.is_err());

    // Accepted when explicitly opted in
    let ok = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: enc.output_b64,
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("v1 decrypt with explicit opt-in");
    assert_eq!(B64.decode(&ok.plaintext_b64).unwrap(), b"Legacy v1 SEIPD test");
    assert_eq!(ok.seipd_version, 1);
}

#[test]
fn test_rejects_tampered_and_truncated_ciphertext() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice"), "alice-passphrase-1234");

    let enc = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(b"Sensitive plaintext must never leak on tamper!"),
            recipient_fingerprints: vec![alice.summary.fingerprint.clone()],
            sign_fingerprint: None,
            sign_passphrase: None,
            profile: Some("rfc9580".into()),
            armor: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("encrypt");

    let raw = B64.decode(&enc.output_b64).unwrap();

    // 1. Bit flip in ciphertext body / AEAD tag
    let mut tampered = raw.clone();
    let last = tampered.len() - 5;
    tampered[last] ^= 0x01;
    let res_tamper = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(&tampered),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    );
    assert!(res_tamper.is_err(), "tampered ciphertext must be rejected");

    // 2. Truncated ciphertext
    let truncated = &raw[..raw.len() - 12];
    let res_trunc = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(truncated),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    );
    assert!(res_trunc.is_err(), "truncated ciphertext must be rejected");
}

#[test]
fn test_rejects_unauthenticated_sed_packet() {
    let store = SessionStore::default();
    // Minimal synthetic Tag 9 (SymEncryptedData) packet header (new format: 0xC0 | 9 = 0xC9, len=10)
    let mut sed_pkt = vec![0xC9, 0x0A];
    sed_pkt.extend_from_slice(&[0x42u8; 10]);

    let res = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(&sed_pkt),
            passphrase: Some("anything".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    );
    assert!(res.is_err());
    let msg = res.err().unwrap();
    assert!(
        msg.contains("SED") || msg.contains("unauthenticated"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_detached_sign_and_verify() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice-signer"), "alice-passphrase-1234");
    let data = b"Release artifact payload v1.0.0";

    let signed = sign_detached(
        &store,
        SignDetachedRequest {
            data_b64: B64.encode(data),
            sign_fingerprint: alice.summary.fingerprint.clone(),
            passphrase: "alice-passphrase-1234".into(),
            armor: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("detached sign");

    let arm = signed.signature_armored.as_ref().unwrap();
    assert!(!armor_has_forbidden_headers(arm));

    let verified = verify_detached(
        &store,
        VerifyDetachedRequest {
            data_b64: B64.encode(data),
            signature_b64: signed.signature_b64.clone(),
            now_secs: TEST_NOW,
        },
    )
    .expect("verify");
    assert_eq!(verified.status, "valid");
    assert_eq!(
        verified.signer_fingerprint.as_deref(),
        Some(alice.summary.fingerprint.as_str())
    );

    // Tampered data must fail verification
    let bad = verify_detached(
        &store,
        VerifyDetachedRequest {
            data_b64: B64.encode(b"Release artifact payload v1.0.1"),
            signature_b64: signed.signature_b64,
            now_secs: TEST_NOW,
        },
    )
    .expect("verify returns invalid status");
    assert_eq!(bad.status, "invalid");
}

#[test]
fn test_limits_and_session_wipe() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice"), "alice-passphrase-1234");

    // S2K Argon2 excessive memory limit (m_enc=22 -> 4 GiB) must be rejected
    let huge_s2k = StringToKey::Argon2 {
        salt: [0u8; 16],
        t: 1,
        p: 4,
        m_enc: 22,
    };
    assert!(check_s2k_string_to_key(&huge_s2k).is_err());

    // Oversized input rejected
    let big = vec![0u8; MAX_INPUT_BYTES + 1];
    let err = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(&big),
            recipient_fingerprints: vec![alice.summary.fingerprint.clone()],
            sign_fingerprint: None,
            sign_passphrase: None,
            profile: Some("rfc9580".into()),
            armor: false,
            now_secs: TEST_NOW,
        },
    );
    assert!(err.is_err());

    // Session wipe removes all keys
    assert_eq!(store.list_keys().len(), 1);
    store.wipe();
    assert!(store.list_keys().is_empty());
    assert!(store.secret_keys.is_empty());
}

#[test]
fn test_release_html_detached_signature_and_tamper_rejection() {
    let mut release_signer = SessionStore::default();
    let signer = gen_test_key(
        &mut release_signer,
        Some("release-signing-key"),
        "release-key-passphrase-99",
    );

    // Simulate full standalone HTML artifact payload
    let html_artifact = b"<!DOCTYPE html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"></head><body>Zero-Trace Vault</body></html>";

    let sig = sign_detached(
        &release_signer,
        SignDetachedRequest {
            data_b64: B64.encode(html_artifact),
            sign_fingerprint: signer.summary.fingerprint.clone(),
            passphrase: "release-key-passphrase-99".into(),
            armor: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("detached sign over HTML artifact");

    // Independent verifier importing only the public signing key
    let mut verifier = SessionStore::default();
    import_keys(
        &mut verifier,
        ImportKeyRequest {
            data_b64: B64.encode(signer.public_key_armored.as_bytes()),
        },
    )
    .expect("import public release key");

    let ok = verify_detached(
        &verifier,
        VerifyDetachedRequest {
            data_b64: B64.encode(html_artifact),
            signature_b64: sig.signature_b64.clone(),
            now_secs: TEST_NOW,
        },
    )
    .expect("verify original HTML");
    assert_eq!(ok.status, "valid");

    // Modify 1 byte in HTML copy -> verification MUST fail
    let mut tampered_html = html_artifact.to_vec();
    tampered_html[20] ^= 0x01;
    let bad = verify_detached(
        &verifier,
        VerifyDetachedRequest {
            data_b64: B64.encode(&tampered_html),
            signature_b64: sig.signature_b64,
            now_secs: TEST_NOW,
        },
    )
    .expect("verify tampered HTML");
    assert_eq!(bad.status, "invalid");
}

// ============================================================================
// Regression Tests: Finding 1 (Hardened Key Selection) & Finding 3 (Anon PKESK Budget)
// ============================================================================

struct SubkeySpec {
    key_type: pgp::composed::KeyType,
    flags: Option<pgp::packet::KeyFlags>,
    expiration_secs: Option<u32>,
    revoked: bool,
    with_backsig: bool,
}

/// Builds a synthetic RFC 9580 v6 secret key with configurable primary flags/expiration/revocation
/// and arbitrary subkeys (unencrypted secret params for fast deterministic tests).
fn build_custom_v6_key(
    created_secs: u32,
    primary_flags: Option<pgp::packet::KeyFlags>,
    primary_expiration_secs: Option<u32>,
    primary_revoked: bool,
    subkey_specs: &[SubkeySpec],
) -> pgp::composed::SignedSecretKey {
    use pgp::composed::{KeyType, SignedKeyDetails, SignedSecretKey, SignedSecretSubKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{
        PubKeyInner, PublicKey as PacketPublicKey, PublicSubkey as PacketPublicSubkey,
        SecretKey as PacketSecretKey, SecretSubkey as PacketSecretSubkey, SignatureConfig,
        SignatureType, Subpacket, SubpacketData,
    };
    use pgp::types::{Duration, KeyDetails, KeyVersion, Password, Timestamp};

    let mut rng = crate::crypto::VaultRng;
    let created = Timestamp::from_secs(created_secs);
    let pw = Password::empty();

    let (pub_params, sec_params) = KeyType::Ed25519.generate(&mut rng).unwrap();
    let pub_inner =
        PubKeyInner::new(KeyVersion::V6, KeyType::Ed25519.to_alg(), created, None, pub_params)
            .unwrap();
    let primary_pub = PacketPublicKey::from_inner(pub_inner).unwrap();
    let primary_key = PacketSecretKey::new(primary_pub.clone(), sec_params).unwrap();

    let mut dks_cfg = SignatureConfig::v6(
        &mut rng,
        SignatureType::Key,
        primary_key.algorithm(),
        HashAlgorithm::Sha256,
    )
    .unwrap();
    dks_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
    );
    dks_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint())).unwrap(),
    );
    if let Some(flags) = primary_flags {
        dks_cfg
            .hashed_subpackets
            .push(Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap());
    }
    if let Some(exp) = primary_expiration_secs {
        dks_cfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(exp))).unwrap(),
        );
    }
    let dks = dks_cfg.sign_key(&primary_key, &pw, &primary_pub).unwrap();

    let mut rev_sigs = Vec::new();
    if primary_revoked {
        let mut rev_cfg = SignatureConfig::v6(
            &mut rng,
            SignatureType::KeyRevocation,
            primary_key.algorithm(),
            HashAlgorithm::Sha256,
        )
        .unwrap();
        rev_cfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                created_secs + 10,
            )))
            .unwrap(),
        );
        rev_cfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
                .unwrap(),
        );
        let rev_sig = rev_cfg.sign_key(&primary_key, &pw, &primary_pub).unwrap();
        rev_sigs.push(rev_sig);
    }

    let mut signed_subkeys = Vec::new();
    for spec in subkey_specs {
        let (spub, ssec) = spec.key_type.generate(&mut rng).unwrap();
        let sinner =
            PubKeyInner::new(KeyVersion::V6, spec.key_type.to_alg(), created, None, spub).unwrap();
        let sub_pub = PacketPublicSubkey::from_inner(sinner).unwrap();
        let sub_key = PacketSecretSubkey::new(sub_pub.clone(), ssec).unwrap();

        let mut bcfg = SignatureConfig::v6(
            &mut rng,
            SignatureType::SubkeyBinding,
            primary_key.algorithm(),
            HashAlgorithm::Sha256,
        )
        .unwrap();
        bcfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
        );
        bcfg.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
                .unwrap(),
        );
        if let Some(ref flags) = spec.flags {
            bcfg.hashed_subpackets
                .push(Subpacket::regular(SubpacketData::KeyFlags(flags.clone())).unwrap());
        }
        if let Some(exp) = spec.expiration_secs {
            bcfg.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(exp)))
                    .unwrap(),
            );
        }
        if spec.with_backsig {
            let mut back_cfg = SignatureConfig::v6(
                &mut rng,
                SignatureType::KeyBinding,
                sub_key.algorithm(),
                HashAlgorithm::Sha256,
            )
            .unwrap();
            back_cfg.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
            );
            back_cfg.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::IssuerFingerprint(sub_key.fingerprint()))
                    .unwrap(),
            );
            let backsig = back_cfg
                .sign_primary_key_binding(&sub_key, &sub_pub, &pw, &primary_pub)
                .unwrap();
            bcfg.unhashed_subpackets.push(
                Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(backsig))).unwrap(),
            );
        }

        let binding = bcfg
            .sign_subkey_binding(&primary_key, &primary_pub, &pw, &sub_pub)
            .unwrap();
        let mut sigs = vec![binding];

        if spec.revoked {
            let mut rcfg = SignatureConfig::v6(
                &mut rng,
                SignatureType::SubkeyRevocation,
                primary_key.algorithm(),
                HashAlgorithm::Sha256,
            )
            .unwrap();
            rcfg.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    created_secs + 10,
                )))
                .unwrap(),
            );
            rcfg.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
                    .unwrap(),
            );
            let rsig = rcfg
                .sign_subkey_binding(&primary_key, &primary_pub, &pw, &sub_pub)
                .unwrap();
            sigs.push(rsig);
        }

        signed_subkeys.push(SignedSecretSubKey::new(sub_key, sigs));
    }

    let details = SignedKeyDetails::new(rev_sigs, vec![dks], vec![], vec![]);
    SignedSecretKey::new(primary_key, details, vec![], signed_subkeys)
}

#[test]
fn test_key_selection_rejects_expired_revoked_wrong_flags_and_missing_flags() {
    use crate::key_select::{select_encryption_target, select_signing_target};
    use pgp::composed::KeyType;
    use pgp::packet::KeyFlags;

    let mut certify_sign = KeyFlags::default();
    certify_sign.set_certify(true);
    certify_sign.set_sign(true);

    let mut enc_flags = KeyFlags::default();
    enc_flags.set_encrypt_comms(true);

    let mut auth_only = KeyFlags::default();
    auth_only.set_authentication(true);

    let now = TEST_NOW + 1_000;

    // 1. Expired encryption subkey -> rejected
    let expired_sub = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign.clone()),
        None,
        false,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: Some(enc_flags.clone()),
            expiration_secs: Some(500),
            revoked: false,
            with_backsig: false,
        }],
    );
    let err = select_encryption_target(&expired_sub.to_public_key(), now)
        .err()
        .expect("expired subkey must be rejected");
    assert!(err.contains("expired"), "unexpected error: {err}");

    // 2. Revoked encryption subkey -> rejected
    let revoked_sub = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign.clone()),
        None,
        false,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: Some(enc_flags.clone()),
            expiration_secs: None,
            revoked: true,
            with_backsig: false,
        }],
    );
    let err = select_encryption_target(&revoked_sub.to_public_key(), now)
        .err()
        .expect("revoked subkey must be rejected");
    assert!(err.contains("revoked"), "unexpected error: {err}");

    // 3. Wrong-purpose subkey (auth-only flag on X25519) -> rejected
    let wrong_flags = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign.clone()),
        None,
        false,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: Some(auth_only.clone()),
            expiration_secs: None,
            revoked: false,
            with_backsig: false,
        }],
    );
    let err = select_encryption_target(&wrong_flags.to_public_key(), now)
        .err()
        .expect("wrong-purpose subkey must be rejected");
    assert!(err.contains("wrong-purpose"), "unexpected error: {err}");

    // 4. Legacy subkey without explicit KeyFlags subpacket -> fail-closed rejection
    let no_flags = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign.clone()),
        None,
        false,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: None,
            expiration_secs: None,
            revoked: false,
            with_backsig: false,
        }],
    );
    let err = select_encryption_target(&no_flags.to_public_key(), now)
        .err()
        .expect("legacy subkey without KeyFlags must be rejected");
    assert!(err.contains("Key Flags"), "unexpected error: {err}");

    // 5. Revoked primary key -> rejected for both encrypt and sign
    let revoked_primary = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign.clone()),
        None,
        true,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: Some(enc_flags.clone()),
            expiration_secs: None,
            revoked: false,
            with_backsig: false,
        }],
    );
    assert!(select_encryption_target(&revoked_primary.to_public_key(), now).is_err());
    assert!(select_signing_target(&revoked_primary, now).is_err());

    // 6. Expired primary key -> rejected for both encrypt and sign
    let expired_primary = build_custom_v6_key(
        TEST_NOW,
        Some(certify_sign),
        Some(500),
        false,
        &[SubkeySpec {
            key_type: KeyType::X25519,
            flags: Some(enc_flags),
            expiration_secs: None,
            revoked: false,
            with_backsig: false,
        }],
    );
    assert!(select_encryption_target(&expired_primary.to_public_key(), now).is_err());
    assert!(select_signing_target(&expired_primary, now).is_err());
}

#[test]
fn test_key_selection_skips_unsuitable_first_subkey_and_picks_later_valid_subkey() {
    use crate::key_select::{select_encryption_target, select_signing_target, EncTarget, SignTarget};
    use pgp::composed::KeyType;
    use pgp::packet::KeyFlags;
    use pgp::types::KeyDetails;

    let mut certify_only = KeyFlags::default();
    certify_only.set_certify(true);

    let mut enc_flags = KeyFlags::default();
    enc_flags.set_encrypt_comms(true);

    let mut sign_flags = KeyFlags::default();
    sign_flags.set_sign(true);

    let mut auth_only = KeyFlags::default();
    auth_only.set_authentication(true);

    let now = TEST_NOW + 1_000;

    let sk = build_custom_v6_key(
        TEST_NOW,
        Some(certify_only),
        None,
        false,
        &[
            // Subkey 0: expired encryption subkey
            SubkeySpec {
                key_type: KeyType::X25519,
                flags: Some(enc_flags.clone()),
                expiration_secs: Some(500),
                revoked: false,
                with_backsig: false,
            },
            // Subkey 1: revoked encryption subkey
            SubkeySpec {
                key_type: KeyType::X25519,
                flags: Some(enc_flags.clone()),
                expiration_secs: None,
                revoked: true,
                with_backsig: false,
            },
            // Subkey 2: wrong-purpose X25519 (auth-only)
            SubkeySpec {
                key_type: KeyType::X25519,
                flags: Some(auth_only),
                expiration_secs: None,
                revoked: false,
                with_backsig: false,
            },
            // Subkey 3: VALID encryption subkey
            SubkeySpec {
                key_type: KeyType::X25519,
                flags: Some(enc_flags),
                expiration_secs: Some(86_400),
                revoked: false,
                with_backsig: false,
            },
            // Subkey 4: expired signing subkey
            SubkeySpec {
                key_type: KeyType::Ed25519,
                flags: Some(sign_flags.clone()),
                expiration_secs: Some(500),
                revoked: false,
                with_backsig: true,
            },
            // Subkey 5: revoked signing subkey
            SubkeySpec {
                key_type: KeyType::Ed25519,
                flags: Some(sign_flags.clone()),
                expiration_secs: None,
                revoked: true,
                with_backsig: true,
            },
            // Subkey 6: VALID signing subkey with backsig
            SubkeySpec {
                key_type: KeyType::Ed25519,
                flags: Some(sign_flags),
                expiration_secs: Some(86_400),
                revoked: false,
                with_backsig: true,
            },
        ],
    );

    let pk = sk.to_public_key();
    let expected_enc_fp = pk.public_subkeys[3].key.fingerprint();
    let expected_sign_fp = sk.secret_subkeys[6].key.fingerprint();

    match select_encryption_target(&pk, now).expect("should select 4th subkey") {
        EncTarget::Subkey(k) => assert_eq!(k.fingerprint(), expected_enc_fp),
        EncTarget::Primary(_) => panic!("expected encryption subkey 3"),
    }

    match select_signing_target(&sk, now).expect("should select 7th subkey") {
        SignTarget::Subkey(k) => assert_eq!(k.fingerprint(), expected_sign_fp),
        SignTarget::Primary(_) => panic!("expected signing subkey 6"),
    }

    // End-to-end encrypt + inline sign + decrypt + verify with this multi-subkey bundle
    let mut store = SessionStore::default();
    let summary = store.upsert_secret(sk, true);

    let enc = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(b"Multi-subkey selection works"),
            recipient_fingerprints: vec![summary.fingerprint.clone()],
            sign_fingerprint: Some(summary.fingerprint.clone()),
            sign_passphrase: Some(String::new()),
            profile: Some("rfc9580".into()),
            armor: true,
            now_secs: now,
        },
    )
    .expect("encrypt with later valid subkeys");

    let dec = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: enc.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: now,
        },
    )
    .expect("decrypt with later valid subkeys");
    assert_eq!(B64.decode(&dec.plaintext_b64).unwrap(), b"Multi-subkey selection works");
    assert_eq!(dec.signature.status, "valid");

    // Detached sign + verify also uses the valid signing subkey
    let detached = sign_detached(
        &store,
        SignDetachedRequest {
            data_b64: B64.encode(b"Detached subkey payload"),
            sign_fingerprint: summary.fingerprint,
            passphrase: String::new(),
            armor: true,
            now_secs: now,
        },
    )
    .expect("detached sign with later valid signing subkey");
    let verified = verify_detached(
        &store,
        VerifyDetachedRequest {
            data_b64: B64.encode(b"Detached subkey payload"),
            signature_b64: detached.signature_b64,
            now_secs: now,
        },
    )
    .expect("verify detached subkey sig");
    assert_eq!(verified.status, "valid");
}

#[test]
fn test_anon_pkesk_budget_multi_subkey_below_at_and_above_limit() {
    use pgp::composed::KeyType;
    use pgp::packet::KeyFlags;

    let mut certify_sign = KeyFlags::default();
    certify_sign.set_certify(true);
    certify_sign.set_sign(true);

    let mut enc_flags = KeyFlags::default();
    enc_flags.set_encrypt_comms(true);

    let make_bundle = |subkey_count: usize| {
        let specs: Vec<SubkeySpec> = (0..subkey_count)
            .map(|_| SubkeySpec {
                key_type: KeyType::X25519,
                flags: Some(enc_flags.clone()),
                expiration_secs: None,
                revoked: false,
                with_backsig: false,
            })
            .collect();
        build_custom_v6_key(TEST_NOW, Some(certify_sign.clone()), None, false, &specs)
    };

    // Helper: create a message with `anon_pkesks` anonymous v6 PKESK packets encrypted to `target_fp`
    let encrypt_with_n_anon_pkesks = |store: &SessionStore, target_fp: &str, n: usize| {
        let recipients = vec![target_fp.to_string(); n];
        encrypt_message(
            store,
            EncryptRequest {
                plaintext_b64: B64.encode(b"Budget test payload"),
                recipient_fingerprints: recipients,
                sign_fingerprint: None,
                sign_passphrase: None,
                profile: Some("rfc9580".into()),
                armor: false,
                now_secs: TEST_NOW,
            },
        )
        .expect("encrypt with N anonymous PKESKs")
    };

    // Case A: 1 key bundle with 14 subkeys (15 candidate keys) × 2 anon PKESKs = 30 < 32 (below limit)
    let mut store_below = SessionStore::default();
    let s_below = store_below.upsert_secret(make_bundle(14), true);
    let msg_below = encrypt_with_n_anon_pkesks(&store_below, &s_below.fingerprint, 2);
    let dec_below = decrypt_message(
        &store_below,
        DecryptRequest {
            input_b64: msg_below.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    );
    assert!(dec_below.is_ok(), "30 attempts (< 32) must be allowed");

    // Case B: 1 key bundle with 15 subkeys (16 candidate keys) × 2 anon PKESKs = 32 == 32 (at limit)
    let mut store_at = SessionStore::default();
    let s_at = store_at.upsert_secret(make_bundle(15), true);
    let msg_at = encrypt_with_n_anon_pkesks(&store_at, &s_at.fingerprint, 2);
    let dec_at = decrypt_message(
        &store_at,
        DecryptRequest {
            input_b64: msg_at.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    );
    assert!(dec_at.is_ok(), "32 attempts (== 32) must be allowed");

    // Case C: 1 key bundle with 16 subkeys (17 candidate keys) × 2 anon PKESKs = 34 > 32 (above limit)
    let mut store_above_sub = SessionStore::default();
    let s_above_sub = store_above_sub.upsert_secret(make_bundle(16), true);
    let msg_above_sub = encrypt_with_n_anon_pkesks(&store_above_sub, &s_above_sub.fingerprint, 2);
    let err_above_sub = decrypt_message(
        &store_above_sub,
        DecryptRequest {
            input_b64: msg_above_sub.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .err()
    .expect("34 attempts (> 32) must be rejected");
    assert!(err_above_sub.contains("34 > 32"), "unexpected error: {err_above_sub}");

    // Case D: Single anon PKESK with 32 subkeys (33 candidate keys) = 33 > 32 (directly above limit)
    let mut store_33 = SessionStore::default();
    let s_33 = store_33.upsert_secret(make_bundle(32), true);
    let msg_33 = encrypt_with_n_anon_pkesks(&store_33, &s_33.fingerprint, 1);
    let err_33 = decrypt_message(
        &store_33,
        DecryptRequest {
            input_b64: msg_33.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .err()
    .expect("33 attempts (> 32) must be rejected");
    assert!(err_33.contains("33 > 32"), "unexpected error: {err_33}");

    // Case E: 3 anonymous PKESKs with 10 subkeys (11 candidate keys) = 33 > 32 -> rejected
    let mut store_3p = SessionStore::default();
    let s_3p = store_3p.upsert_secret(make_bundle(10), true);
    let msg_3p = encrypt_with_n_anon_pkesks(&store_3p, &s_3p.fingerprint, 3);
    let err_3p = decrypt_message(
        &store_3p,
        DecryptRequest {
            input_b64: msg_3p.output_b64,
            passphrase: Some(String::new()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .err()
    .expect("3 anon PKESKs × 11 keys = 33 (> 32) must be rejected");
    assert!(err_3p.contains("33 > 32"), "unexpected error: {err_3p}");
}

#[test]
fn test_signature_verification_rejects_revoked_expired_and_unbacksigged_keys() {
    use pgp::composed::{DetachedSignature, KeyType};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::KeyFlags;
    use pgp::types::Password;
    use std::io::Cursor;

    let mut certify_only = KeyFlags::default();
    certify_only.set_certify(true);

    let mut certify_sign = KeyFlags::default();
    certify_sign.set_certify(true);
    certify_sign.set_sign(true);

    let mut sign_flags = KeyFlags::default();
    sign_flags.set_sign(true);

    let payload = b"Verification key-eligibility regression payload";
    let pw = Password::empty();
    let mut rng = crate::crypto::VaultRng;

    // 1. Revoked primary key: sign directly with primary_key, verify must NOT return "valid"
    let revoked_primary = build_custom_v6_key(TEST_NOW, Some(certify_sign.clone()), None, true, &[]);
    let sig_revoked = DetachedSignature::sign_binary_data(
        &mut rng,
        &revoked_primary.primary_key,
        &pw,
        HashAlgorithm::Sha256,
        Cursor::new(payload),
    )
    .expect("raw sign");
    let sig_revoked_b64 = B64.encode(sig_revoked.to_armored_string(Default::default()).unwrap().as_bytes());
    let mut store_rev = SessionStore::default();
    store_rev.upsert_public(revoked_primary.to_public_key(), true);
    let ver_rev = verify_detached(
        &store_rev,
        VerifyDetachedRequest {
            data_b64: B64.encode(payload),
            signature_b64: sig_revoked_b64,
            now_secs: TEST_NOW + 100,
        },
    )
    .expect("verify returns result");
    assert_eq!(ver_rev.status, "invalid", "revoked primary key signature must be rejected");

    // 2. Expired primary key -> rejected
    let expired_primary = build_custom_v6_key(TEST_NOW, Some(certify_sign), Some(50), false, &[]);
    let sig_exp = DetachedSignature::sign_binary_data(
        &mut rng,
        &expired_primary.primary_key,
        &pw,
        HashAlgorithm::Sha256,
        Cursor::new(payload),
    )
    .expect("raw sign");
    let sig_exp_b64 = B64.encode(sig_exp.to_armored_string(Default::default()).unwrap().as_bytes());
    let mut store_exp = SessionStore::default();
    store_exp.upsert_public(expired_primary.to_public_key(), true);
    let ver_exp = verify_detached(
        &store_exp,
        VerifyDetachedRequest {
            data_b64: B64.encode(payload),
            signature_b64: sig_exp_b64,
            now_secs: TEST_NOW + 100,
        },
    )
    .expect("verify returns result");
    assert_eq!(ver_exp.status, "invalid", "expired primary key signature must be rejected");

    // 3. Signing subkey WITHOUT embedded Primary Key Binding backsignature -> rejected
    let no_backsig = build_custom_v6_key(
        TEST_NOW,
        Some(certify_only.clone()),
        None,
        false,
        &[SubkeySpec {
            key_type: KeyType::Ed25519,
            flags: Some(sign_flags.clone()),
            expiration_secs: None,
            revoked: false,
            with_backsig: false,
        }],
    );
    let sig_nobacksig = DetachedSignature::sign_binary_data(
        &mut rng,
        &no_backsig.secret_subkeys[0].key,
        &pw,
        HashAlgorithm::Sha256,
        Cursor::new(payload),
    )
    .expect("raw subkey sign");
    let sig_nobacksig_b64 =
        B64.encode(sig_nobacksig.to_armored_string(Default::default()).unwrap().as_bytes());
    let mut store_nb = SessionStore::default();
    store_nb.upsert_public(no_backsig.to_public_key(), true);
    let ver_nb = verify_detached(
        &store_nb,
        VerifyDetachedRequest {
            data_b64: B64.encode(payload),
            signature_b64: sig_nobacksig_b64,
            now_secs: TEST_NOW + 100,
        },
    )
    .expect("verify returns result");
    assert_eq!(
        ver_nb.status, "invalid",
        "signing subkey without backsignature must be rejected during verification"
    );

    // 4. Primary key with Certify-only flag (no Sign flag) -> rejected
    let cert_only_key = build_custom_v6_key(TEST_NOW, Some(certify_only), None, false, &[]);
    let sig_cert = DetachedSignature::sign_binary_data(
        &mut rng,
        &cert_only_key.primary_key,
        &pw,
        HashAlgorithm::Sha256,
        Cursor::new(payload),
    )
    .expect("raw cert-only sign");
    let sig_cert_b64 = B64.encode(sig_cert.to_armored_string(Default::default()).unwrap().as_bytes());
    let mut store_co = SessionStore::default();
    store_co.upsert_public(cert_only_key.to_public_key(), true);
    let ver_co = verify_detached(
        &store_co,
        VerifyDetachedRequest {
            data_b64: B64.encode(payload),
            signature_b64: sig_cert_b64,
            now_secs: TEST_NOW + 100,
        },
    )
    .expect("verify returns result");
    assert_eq!(
        ver_co.status, "invalid",
        "certify-only key without Sign flag must be rejected during verification"
    );
}

#[test]
fn test_rejects_v1_seipd_tamper_truncation_and_multi_seipd_smuggling() {
    let mut store = SessionStore::default();
    let alice = gen_test_key(&mut store, Some("alice"), "alice-passphrase-1234");

    let enc_v1 = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(b"Legacy v1 integrity check payload"),
            recipient_fingerprints: vec![alice.summary.fingerprint.clone()],
            sign_fingerprint: None,
            sign_passphrase: None,
            profile: Some("compat_seipd_v1".into()),
            armor: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("encrypt v1");
    let raw_v1 = B64.decode(&enc_v1.output_b64).unwrap();

    // 1. Tampered v1-SEIPD+MDC must fail
    let mut tampered = raw_v1.clone();
    let idx = tampered.len() - 4;
    tampered[idx] ^= 0x01;
    assert!(decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(&tampered),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    )
    .is_err());

    // 2. Truncated v1-SEIPD+MDC must fail
    let truncated = &raw_v1[..raw_v1.len() - 10];
    assert!(decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(truncated),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    )
    .is_err());

    // 3. Smuggling two SEIPD packets (v1 followed by v2) must be rejected
    let enc_v2 = encrypt_message(
        &store,
        EncryptRequest {
            plaintext_b64: B64.encode(b"v2 payload"),
            recipient_fingerprints: vec![alice.summary.fingerprint.clone()],
            sign_fingerprint: None,
            sign_passphrase: None,
            profile: Some("rfc9580".into()),
            armor: false,
            now_secs: TEST_NOW,
        },
    )
    .expect("encrypt v2");
    let mut combined = raw_v1;
    combined.extend_from_slice(&B64.decode(&enc_v2.output_b64).unwrap());
    let err = decrypt_message(
        &store,
        DecryptRequest {
            input_b64: B64.encode(&combined),
            passphrase: Some("alice-passphrase-1234".into()),
            allow_legacy_seipd_v1: false,
            now_secs: TEST_NOW,
        },
    )
    .err()
    .expect("multiple SEIPD packets must be rejected");
    assert!(err.contains("SEIPD"), "unexpected error: {err}");
}

#[test]
fn test_compat_rsa4096_keygen_packet_inspection_and_sha256_sha512_interop() {
    use pgp::composed::{
        Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey, SubpacketConfig,
    };
    use pgp::crypto::{
        aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    };
    use pgp::packet::{SignatureVersion, SubpacketData};
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, KeyVersion, Password, PublicParams, S2kParams, SecretParams};
    use std::io::Cursor;

    let rsa_modulus_bits = |rsa_pub: &pgp::types::RsaPublicParams| -> usize {
        let mut buf = Vec::new();
        rsa_pub.to_writer(&mut buf).expect("serialize RSA public params");
        u16::from_be_bytes([buf[0], buf[1]]) as usize
    };

    let mut store = SessionStore::default();

    // 1. Explicit compatibility failure checks:
    //    (a) Missing / short passphrase rejected
    let err_pw = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: Some("Alice RSA <alice@example.invalid>".into()),
            passphrase: "short".into(),
            profile: Some("compat_rsa4096".into()),
            now_secs: TEST_NOW,
        },
    );
    assert!(err_pw.is_err(), "short passphrase must be rejected");

    //    (b) Empty User ID rejected explicitly on v4 Compatibility profile
    let err_uid = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: Some("   ".into()),
            passphrase: "kleopatra-rsa4096-passphrase".into(),
            profile: Some("compat_rsa4096".into()),
            now_secs: TEST_NOW,
        },
    )
    .err()
    .expect("empty User ID must be rejected for v4 Compatibility profile");
    assert!(
        err_uid.contains("User ID"),
        "expected explicit User ID error, got: {err_uid}"
    );

    //    (c) Unknown profile rejected explicitly
    let err_prof = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: Some("Alice".into()),
            passphrase: "kleopatra-rsa4096-passphrase".into(),
            profile: Some("unknown_profile".into()),
            now_secs: TEST_NOW,
        },
    );
    assert!(err_prof.is_err());

    // 2. Verify Modern (default) profile still uses v6 Ed25519 + X25519 and Argon2 + AES-256-OCB
    let modern = gen_test_key(&mut store, Some("Modern User"), "modern-v6-passphrase-123");
    let (modern_sk, _) =
        SignedSecretKey::from_string(&modern.secret_key_armored).expect("parse modern sk");
    assert_eq!(modern_sk.primary_key.version(), KeyVersion::V6);
    assert_eq!(modern_sk.primary_key.algorithm(), PublicKeyAlgorithm::Ed25519);
    assert_eq!(modern_sk.secret_subkeys.len(), 1);
    assert_eq!(modern_sk.secret_subkeys[0].key.version(), KeyVersion::V6);
    assert_eq!(
        modern_sk.secret_subkeys[0].key.algorithm(),
        PublicKeyAlgorithm::X25519
    );
    match modern_sk.primary_key.secret_params() {
        SecretParams::Encrypted(enc) => match enc.string_to_key_params() {
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k: StringToKey::Argon2 { t, p, m_enc, .. },
                ..
            } => {
                assert_eq!(*sym_alg, SymmetricKeyAlgorithm::AES256);
                assert_eq!(*aead_mode, AeadAlgorithm::Ocb);
                assert_eq!((*t, *p, *m_enc), (3, 4, 16));
            }
            other => panic!("expected Argon2 + AES-256-OCB on modern v6 key, got {other:?}"),
        },
        other => panic!("expected encrypted modern secret key, got {other:?}"),
    }

    // 3. Generate Compatibility OpenPGP v4 RSA-4096 key and inspect packets, algorithms, Key Flags, and S2K protection
    let compat_pw = "kleopatra-rsa4096-passphrase";
    let compat = generate_key(
        &mut store,
        KeyGenRequest {
            user_id: Some("Alice Compat <alice-rsa@example.invalid>".into()),
            passphrase: compat_pw.into(),
            profile: Some("compat_rsa4096".into()),
            now_secs: TEST_NOW,
        },
    )
    .expect("generate compat_rsa4096 key");

    assert_eq!(compat.summary.version, "V4");
    assert_eq!(compat.summary.algorithm, "RSA");
    assert_eq!(compat.summary.fingerprint.len(), 40); // v4 20-octet SHA-1 fingerprint = 40 hex chars
    assert!(compat.summary.has_secret);
    assert!(compat.summary.can_encrypt);
    assert!(compat.summary.can_sign);
    assert!(!armor_has_forbidden_headers(&compat.public_key_armored));
    assert!(!armor_has_forbidden_headers(&compat.secret_key_armored));

    let (sk, _) = SignedSecretKey::from_string(&compat.secret_key_armored).expect("parse compat sk");
    let (pk, _) = SignedPublicKey::from_string(&compat.public_key_armored).expect("parse compat pk");
    sk.verify_bindings().expect("valid secret key bindings");
    pk.verify_bindings().expect("valid public key bindings");

    // Inspect Primary Key packet: v4, RSA-4096 (4096 bits)
    assert_eq!(sk.primary_key.version(), KeyVersion::V4);
    assert_eq!(sk.primary_key.algorithm(), PublicKeyAlgorithm::RSA);
    match sk.primary_key.public_params() {
        PublicParams::RSA(rsa_pub) => {
            assert_eq!(
                rsa_modulus_bits(rsa_pub),
                4096,
                "primary RSA modulus must be 4096 bits"
            );
        }
        other => panic!("expected RSA public params, got {other:?}"),
    }

    // Inspect Primary Key User ID self-certification signature & Key Flags (Certify + Sign)
    assert!(sk.details.direct_signatures.is_empty(), "v4 key uses User ID self-certification");
    assert_eq!(sk.details.users.len(), 1);
    let uid_sig = &sk.details.users[0].signatures[0];
    assert_eq!(uid_sig.version(), SignatureVersion::V4);
    assert_eq!(uid_sig.hash_alg(), Some(HashAlgorithm::Sha256));
    let pri_flags = uid_sig.key_flags();
    assert!(pri_flags.certify(), "primary RSA key must have Certify flag");
    assert!(pri_flags.sign(), "primary RSA key must have Sign flag");
    assert!(!pri_flags.encrypt_comms(), "primary RSA key must not have EncryptComms flag");
    assert!(!pri_flags.encrypt_storage(), "primary RSA key must not have EncryptStorage flag");

    // Inspect Encryption Subkey packet: v4, RSA-4096 (4096 bits), SubkeyBinding signature & Key Flags (EncryptComms + EncryptStorage)
    assert_eq!(sk.secret_subkeys.len(), 1);
    let sub = &sk.secret_subkeys[0];
    assert_eq!(sub.key.version(), KeyVersion::V4);
    assert_eq!(sub.key.algorithm(), PublicKeyAlgorithm::RSA);
    match sub.key.public_params() {
        PublicParams::RSA(rsa_sub) => {
            assert_eq!(
                rsa_modulus_bits(rsa_sub),
                4096,
                "subkey RSA modulus must be 4096 bits"
            );
        }
        other => panic!("expected RSA subkey public params, got {other:?}"),
    }
    assert_eq!(sub.signatures.len(), 1);
    let sub_sig = &sub.signatures[0];
    assert_eq!(sub_sig.version(), SignatureVersion::V4);
    assert_eq!(sub_sig.hash_alg(), Some(HashAlgorithm::Sha256));
    let sub_flags = sub_sig.key_flags();
    assert!(!sub_flags.certify(), "encryption subkey must not have Certify flag");
    assert!(!sub_flags.sign(), "encryption subkey must not have Sign flag");
    assert!(sub_flags.encrypt_comms(), "encryption subkey must have EncryptComms flag");
    assert!(sub_flags.encrypt_storage(), "encryption subkey must have EncryptStorage flag");

    // Inspect Private-Key Protection on both primary key and subkey:
    // S2K Usage 254 (S2kParams::Cfb) + AES-256 + IteratedAndSalted (SHA-256, count=224) + 20-byte SHA-1 checksum
    for (label, sec_params) in [
        ("primary", sk.primary_key.secret_params()),
        ("subkey", sub.key.secret_params()),
    ] {
        match sec_params {
            SecretParams::Encrypted(enc) => {
                assert_eq!(
                    enc.string_to_key_id(),
                    254,
                    "{label} must use S2K Usage 254 (CFB + SHA-1 checksum)"
                );
                assert_eq!(enc.checksum().len(), 20, "{label} must use 20-octet SHA-1 checksum");
                match enc.string_to_key_params() {
                    S2kParams::Cfb {
                        sym_alg,
                        s2k:
                            StringToKey::IteratedAndSalted {
                                hash_alg, count, ..
                            },
                        iv,
                    } => {
                        assert_eq!(*sym_alg, SymmetricKeyAlgorithm::AES256);
                        assert_eq!(*hash_alg, HashAlgorithm::Sha256);
                        assert_eq!(*count, 224);
                        assert_eq!(iv.len(), 16);
                    }
                    other => panic!("expected Cfb + IteratedAndSalted on {label}, got {other:?}"),
                }
            }
            other => panic!("expected encrypted secret params on {label}, got {other:?}"),
        }
    }

    // 4. Test re-importing the exported RSA-4096 secret key into a fresh vault session,
    //    signing with it (confirming the vault emits SHA-256), and encrypting/decrypting with both
    //    v1-SEIPD+MDC (Kleopatra compatibility write profile) and v2-SEIPD.
    let mut fresh_store = SessionStore::default();
    let imp = import_keys(
        &mut fresh_store,
        ImportKeyRequest {
            data_b64: B64.encode(compat.secret_key_armored.as_bytes()),
        },
    )
    .expect("import exported v4 RSA-4096 secret key into fresh session");
    assert_eq!(imp.imported.len(), 1);
    assert_eq!(imp.imported[0].fingerprint, compat.summary.fingerprint);

    // Detached sign with the RSA-4096 key -> inspect signature hash algorithm (must be SHA-256)
    let msg_bytes = b"Vault RSA-4096 compatibility test message";
    let det_sig = sign_detached(
        &fresh_store,
        SignDetachedRequest {
            data_b64: B64.encode(msg_bytes),
            sign_fingerprint: compat.summary.fingerprint.clone(),
            passphrase: compat_pw.into(),
            armor: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("detached sign with RSA-4096 key");
    let (parsed_det, _) =
        DetachedSignature::from_string(det_sig.signature_armored.as_ref().unwrap())
            .expect("parse detached sig");
    assert_eq!(parsed_det.signature.version(), SignatureVersion::V4);
    assert_eq!(parsed_det.signature.hash_alg(), Some(HashAlgorithm::Sha256));
    let has_issuer_fp = parsed_det
        .signature
        .config()
        .unwrap()
        .hashed_subpackets()
        .any(|sp| matches!(sp.data, SubpacketData::IssuerFingerprint(_)));
    let has_issuer_key_id = parsed_det
        .signature
        .config()
        .unwrap()
        .unhashed_subpackets()
        .any(|sp| matches!(sp.data, SubpacketData::IssuerKeyId(_)));
    assert!(has_issuer_fp, "v4 signature must include hashed IssuerFingerprint");
    assert!(has_issuer_key_id, "v4 signature must include unhashed IssuerKeyId for GnuPG/Kleopatra");

    // Verify SHA-256 detached signature produced by the vault
    let ver_sha256 = verify_detached(
        &fresh_store,
        VerifyDetachedRequest {
            data_b64: B64.encode(msg_bytes),
            signature_b64: det_sig.signature_b64,
            now_secs: TEST_NOW,
        },
    )
    .expect("verify SHA-256 RSA-4096 detached signature");
    assert_eq!(ver_sha256.status, "valid");

    // Create a SHA-512 detached signature with the RSA-4096 primary key (as Kleopatra/GnuPG often emits)
    // and verify that the vault verifies SHA-512 RSA-4096 signatures cleanly!
    let mut rng = crate::crypto::VaultRng;
    let subpackets_512 = SubpacketConfig::UserDefined {
        hashed: vec![
            pgp::packet::Subpacket::regular(SubpacketData::IssuerFingerprint(
                sk.primary_key.fingerprint(),
            ))
            .unwrap(),
            pgp::packet::Subpacket::regular(SubpacketData::SignatureCreationTime(
                pgp::types::Timestamp::from_secs(TEST_NOW),
            ))
            .unwrap(),
        ],
        unhashed: vec![pgp::packet::Subpacket::regular(SubpacketData::IssuerKeyId(
            sk.primary_key.legacy_key_id(),
        ))
        .unwrap()],
    };
    let sig_sha512 = DetachedSignature::sign_binary_data_with_subpackets(
        &mut rng,
        &sk.primary_key,
        &Password::from(compat_pw),
        HashAlgorithm::Sha512,
        Cursor::new(msg_bytes),
        subpackets_512,
    )
    .expect("sign with SHA-512");
    assert_eq!(sig_sha512.signature.hash_alg(), Some(HashAlgorithm::Sha512));
    let sig_sha512_armored = sig_sha512.to_armored_string(Default::default()).unwrap();

    let ver_sha512 = verify_detached(
        &fresh_store,
        VerifyDetachedRequest {
            data_b64: B64.encode(msg_bytes),
            signature_b64: B64.encode(sig_sha512_armored.as_bytes()),
            now_secs: TEST_NOW,
        },
    )
    .expect("verify SHA-512 RSA-4096 detached signature");
    assert_eq!(
        ver_sha512.status, "valid",
        "vault must verify SHA-512 signatures with RSA-4096 keys"
    );

    // Encrypt + inline sign to the RSA-4096 key using Compatibility write profile (v1-SEIPD + v3-PKESK)
    // and decrypt + verify in the vault
    let enc_compat = encrypt_message(
        &fresh_store,
        EncryptRequest {
            plaintext_b64: B64.encode(msg_bytes),
            recipient_fingerprints: vec![compat.summary.fingerprint.clone()],
            sign_fingerprint: Some(compat.summary.fingerprint.clone()),
            sign_passphrase: Some(compat_pw.into()),
            profile: Some("compat_seipd_v1".into()),
            armor: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("encrypt compat_seipd_v1 to RSA-4096 subkey");
    assert_eq!(enc_compat.packet_audit.seipd_version, Some(1));
    assert_eq!(enc_compat.packet_audit.pkesk_versions, vec![3]);
    assert!(enc_compat.packet_audit.all_pkesk_anonymous);

    let dec_compat = decrypt_message(
        &fresh_store,
        DecryptRequest {
            input_b64: enc_compat.output_b64,
            passphrase: Some(compat_pw.into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("decrypt compat_seipd_v1 with RSA-4096 subkey");
    assert_eq!(B64.decode(&dec_compat.plaintext_b64).unwrap(), msg_bytes);
    assert_eq!(dec_compat.signature.status, "valid");

    // 5. Simulate importing an external Kleopatra/GnuPG-format passphrase-protected v4 RSA-4096 key
    //    (locked with S2K Usage 254 CFB + IteratedAndSalted + AES-256 and non-anonymous v3-PKESK message)
    let mut kleo_sim_sk = sk.clone();
    let kleo_pw_str = "external-kleopatra-test-passphrase";
    let kleo_pw = Password::from(kleo_pw_str);
    kleo_sim_sk.primary_key.remove_password(&Password::from(compat_pw)).unwrap();
    kleo_sim_sk
        .primary_key
        .set_password(&mut rng, &kleo_pw)
        .unwrap();
    kleo_sim_sk.secret_subkeys[0]
        .key
        .remove_password(&Password::from(compat_pw))
        .unwrap();
    kleo_sim_sk.secret_subkeys[0]
        .key
        .set_password(&mut rng, &kleo_pw)
        .unwrap();
    let kleo_armored = kleo_sim_sk.to_armored_string(Default::default()).unwrap();

    let mut kleo_store = SessionStore::default();
    let kleo_imp = import_keys(
        &mut kleo_store,
        ImportKeyRequest {
            data_b64: B64.encode(kleo_armored.as_bytes()),
        },
    )
    .expect("import external passphrase-protected v4 RSA-4096 key");
    assert_eq!(kleo_imp.imported.len(), 1);

    // Build a standard GnuPG/Kleopatra-style v1-SEIPD message with non-anonymous v3-PKESK (carries subkey Key ID)
    // and inline SHA-512 signature from the primary key
    let kleo_sub_pub = kleo_sim_sk.secret_subkeys[0].key.public_key();
    let mut builder =
        pgp::composed::MessageBuilder::from_bytes("kleopatra.txt", b"Message from Kleopatra".to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(&mut rng, &kleo_sub_pub)
        .expect("non-anonymous v3 PKESK");
    let subpackets_inline_512 = SubpacketConfig::UserDefined {
        hashed: vec![
            pgp::packet::Subpacket::regular(SubpacketData::IssuerFingerprint(
                kleo_sim_sk.primary_key.fingerprint(),
            ))
            .unwrap(),
            pgp::packet::Subpacket::regular(SubpacketData::SignatureCreationTime(
                pgp::types::Timestamp::from_secs(TEST_NOW),
            ))
            .unwrap(),
        ],
        unhashed: vec![pgp::packet::Subpacket::regular(SubpacketData::IssuerKeyId(
            kleo_sim_sk.primary_key.legacy_key_id(),
        ))
        .unwrap()],
    };
    builder.sign_with_subpackets(
        &kleo_sim_sk.primary_key,
        Password::from(kleo_pw_str),
        HashAlgorithm::Sha512,
        subpackets_inline_512,
    );
    let kleo_msg_armored = builder
        .to_armored_string(&mut rng, Default::default())
        .expect("serialize Kleopatra-style message");

    let kleo_dec = decrypt_message(
        &kleo_store,
        DecryptRequest {
            input_b64: B64.encode(kleo_msg_armored.as_bytes()),
            passphrase: Some(kleo_pw_str.into()),
            allow_legacy_seipd_v1: true,
            now_secs: TEST_NOW,
        },
    )
    .expect("decrypt Kleopatra-style v1-SEIPD + non-anon v3-PKESK + SHA-512 signed message");
    assert_eq!(
        B64.decode(&kleo_dec.plaintext_b64).unwrap(),
        b"Message from Kleopatra"
    );
    assert_eq!(kleo_dec.signature.status, "valid");
}
