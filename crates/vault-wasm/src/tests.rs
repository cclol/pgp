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
            now_secs: TEST_NOW,
        },
    );
    assert!(err.is_err());

    // Pseudonymous / empty UID supported on v6
    let kp = gen_test_key(&mut store, None, "correct-horse-battery-staple");
    assert_eq!(kp.summary.version, "V6");
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
        },
    );
    assert!(res.is_err());
    let msg = res.err().unwrap();
    assert!(
        msg.contains("SED") || msg.contains("Unauthentifiziert"),
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
    assert!(err.contains("abgelaufen"), "unexpected error: {err}");

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
    assert!(err.contains("widerrufen"), "unexpected error: {err}");

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
    assert!(err.contains("zweckfremde"), "unexpected error: {err}");

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
        },
    )
    .err()
    .expect("3 anon PKESKs × 11 keys = 33 (> 32) must be rejected");
    assert!(err_3p.contains("33 > 32"), "unexpected error: {err_3p}");
}
