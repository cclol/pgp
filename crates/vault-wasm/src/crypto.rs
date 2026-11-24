use std::io::{BufReader, Cursor, Read};

use base64::engine::{general_purpose::STANDARD as B64, Engine as _};
use pgp::armor::{Dearmor, DearmorOptions};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, KeyType, Message, MessageBuilder,
    SignedKeyDetails, SignedPublicKey, SignedSecretKey, SignedSecretSubKey, SubpacketConfig,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    Features, KeyFlags, PacketTrait, PubKeyInner, PublicKey as PacketPublicKey,
    PublicSubkey as PacketPublicSubkey, SecretKey as PacketSecretKey,
    SecretSubkey as PacketSecretSubkey, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    UserId,
};
use pgp::types::{
    CompressionAlgorithm, KeyDetails, KeyVersion, PacketHeaderVersion, Password, S2kParams,
    SecretParams, SignedUser, SigningKey, Tag, Timestamp, VerifyingKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::key_select::{
    is_signature_active, select_encryption_target, select_signing_target, select_verifying_keys,
    EncTarget, SignTarget, VerifyTarget,
};
use crate::limits::{
    check_base64_input_size, check_input_size, check_s2k_params, inspect_raw_packets,
    read_all_with_limits, MAX_ANON_DECRYPT_ATTEMPTS, MAX_KEYS_PER_IMPORT, MAX_RECIPIENTS,
    MAX_TOTAL_DECRYPT_ATTEMPTS,
};
use crate::packet_check::{audit_message_packets, estimate_pkesk_decrypt_budget, PacketAudit};
use crate::session::{KeySummary, SessionStore};

/// CSPRNG wrapper backed exclusively by `getrandom` (Web Crypto `crypto.getRandomValues` in Wasm).
/// Aborts on CSPRNG failure rather than ever falling back to a non-cryptographic RNG.
pub struct VaultRng;

impl RngCore for VaultRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("CSPRNG failed: crypto.getRandomValues unavailable or errored");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        #[cfg(target_arch = "wasm32")]
        {
            getrandom::fill(dest).map_err(|_| {
                rand::Error::from(std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap())
            })
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            getrandom_host(dest)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn getrandom_host(dest: &mut [u8]) -> Result<(), rand::Error> {
    // On native targets (unit tests), use OS CSPRNG via rand_core/getrandom 0.2
    let mut os_rng = rand::rngs::OsRng;
    os_rng.try_fill_bytes(dest)
}

impl CryptoRng for VaultRng {}

#[derive(Deserialize)]
pub struct KeyGenRequest {
    pub user_id: Option<String>,
    pub passphrase: String,
    pub profile: Option<String>, // "modern" (default) | "compat_rsa4096"
    pub now_secs: u32,
}

#[derive(Serialize)]
pub struct KeyGenResponse {
    pub summary: KeySummary,
    pub public_key_armored: String,
    pub secret_key_armored: String,
    pub profile: String,
}

#[derive(Deserialize)]
pub struct ImportKeyRequest {
    pub data_b64: String,
}

#[derive(Serialize)]
pub struct ImportKeyResponse {
    pub imported: Vec<KeySummary>,
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub plaintext_b64: String,
    pub recipient_fingerprints: Vec<String>,
    pub sign_fingerprint: Option<String>,
    pub sign_passphrase: Option<String>,
    pub profile: Option<String>, // "rfc9580" (default) | "compat_seipd_v1"
    pub armor: bool,
    pub now_secs: u32,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub output_b64: String,
    pub output_armored: Option<String>,
    pub profile_used: String,
    pub packet_audit: PacketAudit,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub input_b64: String,
    pub passphrase: Option<String>,
    pub allow_legacy_seipd_v1: bool,
    pub now_secs: u32,
}

#[derive(Serialize)]
pub struct SignatureInfo {
    pub status: String, // "none" | "valid" | "invalid" | "unknown_signer"
    pub signer_fingerprint: Option<String>,
    pub signer_user_ids: Vec<String>,
    pub signer_identity_confirmed: bool,
    pub created_at: Option<u32>,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    pub plaintext_b64: String,
    pub seipd_version: u8,
    pub was_compressed: bool,
    pub literal_filename: String,
    pub literal_timestamp: u32,
    pub signature: SignatureInfo,
}

#[derive(Deserialize)]
pub struct SignDetachedRequest {
    pub data_b64: String,
    pub sign_fingerprint: String,
    pub passphrase: String,
    pub armor: bool,
    pub now_secs: u32,
}

#[derive(Serialize)]
pub struct SignDetachedResponse {
    pub signature_b64: String,
    pub signature_armored: Option<String>,
    pub signer_fingerprint: String,
}

#[derive(Deserialize)]
pub struct VerifyDetachedRequest {
    pub data_b64: String,
    pub signature_b64: String,
    pub now_secs: u32,
}

fn build_subpackets(signer: &dyn SigningKey, now_secs: u32) -> Result<SubpacketConfig, String> {
    let ts = Timestamp::from_secs(now_secs);
    let hashed = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(ts))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    let mut unhashed = Vec::new();
    if signer.version() <= KeyVersion::V4 {
        unhashed.push(
            Subpacket::regular(SubpacketData::IssuerKeyId(signer.legacy_key_id()))
                .map_err(|e| format!("Subpacket error: {e}"))?,
        );
    }
    Ok(SubpacketConfig::UserDefined { hashed, unhashed })
}

fn check_secret_key_s2k(sk: &SignedSecretKey) -> Result<(), String> {
    if let SecretParams::Encrypted(enc) = sk.primary_key.secret_params() {
        check_s2k_params(enc.string_to_key_params())?;
    }
    for sub in &sk.secret_subkeys {
        if let SecretParams::Encrypted(enc) = sub.key.secret_params() {
            check_s2k_params(enc.string_to_key_params())?;
        }
    }
    Ok(())
}

fn is_ascii_armored(bytes: &[u8]) -> bool {
    let prefix_len = bytes.len().min(128);
    if let Ok(s) = std::str::from_utf8(&bytes[..prefix_len]) {
        s.trim_start().starts_with("-----BEGIN PGP ")
    } else {
        false
    }
}

fn dearmor_to_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut dearmor = Dearmor::with_options(BufReader::new(Cursor::new(bytes)), DearmorOptions::default());
    dearmor
        .read_header()
        .map_err(|e| format!("Invalid ASCII Armor header: {e}"))?;
    let mut raw = Vec::new();
    dearmor
        .read_to_end(&mut raw)
        .map_err(|e| format!("ASCII Armor decoding failed: {e}"))?;
    check_input_size(raw.len(), "Decoded OpenPGP data")?;
    Ok(raw)
}

pub fn generate_key(store: &mut SessionStore, req: KeyGenRequest) -> Result<KeyGenResponse, String> {
    let passphrase = Zeroizing::new(req.passphrase);
    if passphrase.len() < 8 {
        return Err(
            "Passphrase is required (minimum 8 characters; 12+ characters recommended)."
                .into(),
        );
    }

    let profile = req.profile.as_deref().unwrap_or("modern");
    match profile {
        "modern" | "rfc9580" => generate_key_modern_v6(store, req.user_id, passphrase, req.now_secs),
        "compat_rsa4096" => generate_key_compat_v4_rsa4096(store, req.user_id, passphrase, req.now_secs),
        other => Err(format!(
            "Unsupported key generation profile: '{other}'. Expected 'modern' or 'compat_rsa4096'."
        )),
    }
}

fn generate_key_modern_v6(
    store: &mut SessionStore,
    user_id: Option<String>,
    passphrase: Zeroizing<String>,
    now_secs: u32,
) -> Result<KeyGenResponse, String> {
    let mut rng = VaultRng;
    let created = Timestamp::from_secs(now_secs);
    let pw = Password::from(passphrase.as_str());

    // 1. Generate RFC 9580 v6 Primary Key (Ed25519)
    let (pub_params, sec_params_raw) = KeyType::Ed25519
        .generate(&mut rng)
        .map_err(|e| format!("Ed25519 key generation failed: {e}"))?;
    let primary_pub_inner = PubKeyInner::new(
        KeyVersion::V6,
        KeyType::Ed25519.to_alg(),
        created,
        None,
        pub_params,
    )
    .map_err(|e| format!("Primary key header creation failed: {e}"))?;
    let primary_pub_pkt = PacketPublicKey::from_inner(primary_pub_inner)
        .map_err(|e| format!("Primary public key packet failed: {e}"))?;
    let primary_s2k = S2kParams::new_default(&mut rng, KeyVersion::V6);
    let primary_sec_params = match &sec_params_raw {
        SecretParams::Plain(plain) => SecretParams::Encrypted(
            plain
                .encrypt(
                    passphrase.as_bytes(),
                    primary_s2k,
                    &primary_pub_pkt,
                    Some(Tag::SecretKey),
                )
                .map_err(|e| format!("Primary key encryption failed: {e}"))?,
        ),
        other => other.clone(),
    };
    let primary_key = PacketSecretKey::new(primary_pub_pkt.clone(), primary_sec_params)
        .map_err(|e| format!("Primary secret key packet failed: {e}"))?;

    // 2. Direct Key Signature (RFC 9580 v6) using explicit `created` timestamp (no SystemTime::now!)
    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);

    let mut features = Features::new();
    features.set_seipd_v1(true);
    features.set_seipd_v2(true);

    let mut dks_cfg = SignatureConfig::v6(
        &mut rng,
        SignatureType::Key,
        primary_key.algorithm(),
        HashAlgorithm::Sha256,
    )
    .map_err(|e| format!("Direct key signature configuration failed: {e}"))?;
    dks_cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::Features(features))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            [SymmetricKeyAlgorithm::AES256].into_iter().collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            [HashAlgorithm::Sha256, HashAlgorithm::Sha512]
                .into_iter()
                .collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
            [CompressionAlgorithm::Uncompressed].into_iter().collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(
            [
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb),
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm),
            ]
            .into_iter()
            .collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    let primary_pub_pkt = primary_key.public_key();
    let dks = dks_cfg
        .sign_key(&primary_key, &pw, &primary_pub_pkt)
        .map_err(|e| format!("Direct key signature failed: {e}"))?;

    // 3. Optional User ID with explicit timestamp self-signature
    let mut users = Vec::new();
    if let Some(uid_str) = user_id {
        let trimmed = uid_str.trim();
        if !trimmed.is_empty() {
            let uid = UserId::from_str(PacketHeaderVersion::New, trimmed)
                .map_err(|e| format!("Invalid User ID: {e}"))?;
            let mut uid_cfg = SignatureConfig::v6(
                &mut rng,
                SignatureType::CertPositive,
                primary_key.algorithm(),
                HashAlgorithm::Sha256,
            )
            .map_err(|e| format!("User ID signature configuration failed: {e}"))?;
            uid_cfg.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(created))
                    .map_err(|e| format!("Subpacket error: {e}"))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
                    .map_err(|e| format!("Subpacket error: {e}"))?,
                Subpacket::regular(SubpacketData::IsPrimary(true))
                    .map_err(|e| format!("Subpacket error: {e}"))?,
            ];
            let uid_sig = uid_cfg
                .sign_certification(&primary_key, &primary_pub_pkt, &pw, uid.tag(), &uid)
                .map_err(|e| format!("User ID certification signature failed: {e}"))?;
            users.push(SignedUser::new(uid, vec![uid_sig]));
        }
    }

    // 4. Generate RFC 9580 v6 Encryption Subkey (X25519) + Binding Signature
    let (sub_pub_params, sub_sec_raw) = KeyType::X25519
        .generate(&mut rng)
        .map_err(|e| format!("X25519 subkey generation failed: {e}"))?;
    let sub_pub_inner = PubKeyInner::new(
        KeyVersion::V6,
        KeyType::X25519.to_alg(),
        created,
        None,
        sub_pub_params,
    )
    .map_err(|e| format!("Subkey header creation failed: {e}"))?;
    let sub_pub_pkt = PacketPublicSubkey::from_inner(sub_pub_inner)
        .map_err(|e| format!("Subkey public packet failed: {e}"))?;
    let sub_s2k = S2kParams::new_default(&mut rng, KeyVersion::V6);
    let sub_sec_params = match &sub_sec_raw {
        SecretParams::Plain(plain) => SecretParams::Encrypted(
            plain
                .encrypt(
                    passphrase.as_bytes(),
                    sub_s2k,
                    &sub_pub_pkt,
                    Some(Tag::SecretSubkey),
                )
                .map_err(|e| format!("Subkey encryption failed: {e}"))?,
        ),
        other => other.clone(),
    };
    let sub_key = PacketSecretSubkey::new(sub_pub_pkt, sub_sec_params)
        .map_err(|e| format!("Subkey secret packet failed: {e}"))?;

    let mut sub_flags = KeyFlags::default();
    sub_flags.set_encrypt_comms(true);
    sub_flags.set_encrypt_storage(true);

    let mut sub_cfg = SignatureConfig::v6(
        &mut rng,
        SignatureType::SubkeyBinding,
        primary_key.algorithm(),
        HashAlgorithm::Sha256,
    )
    .map_err(|e| format!("Subkey binding configuration failed: {e}"))?;
    sub_cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::KeyFlags(sub_flags))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    let sub_binding = sub_cfg
        .sign_subkey_binding(&primary_key, &primary_pub_pkt, &pw, &sub_key.public_key())
        .map_err(|e| format!("Subkey binding signature failed: {e}"))?;

    let details = SignedKeyDetails::new(vec![], vec![dks], users, vec![]);
    let secret_key = SignedSecretKey::new(
        primary_key,
        details,
        vec![],
        vec![SignedSecretSubKey::new(sub_key, vec![sub_binding])],
    );

    // Verify self-signatures immediately
    secret_key
        .verify_bindings()
        .map_err(|e| format!("Self-signature verification failed: {e}"))?;

    let public_key = secret_key.to_public_key();
    let armor_opts = ArmorOptions::default(); // headers: None (no Version/Comment)

    let public_key_armored = public_key
        .to_armored_string(armor_opts.clone())
        .map_err(|e| format!("Public key export failed: {e}"))?;
    let secret_key_armored = Zeroizing::new(
        secret_key
            .to_armored_string(armor_opts)
            .map_err(|e| format!("Secret key export failed: {e}"))?,
    );

    // Self-generated key is confirmed by the user in this session
    let summary = store.upsert_secret(secret_key, true);

    Ok(KeyGenResponse {
        summary,
        public_key_armored,
        secret_key_armored: secret_key_armored.to_string(),
        profile: "Modern — OpenPGP v6 (Ed25519 + X25519, Argon2 + AES-256-OCB)".into(),
    })
}

fn generate_key_compat_v4_rsa4096(
    store: &mut SessionStore,
    user_id: Option<String>,
    passphrase: Zeroizing<String>,
    now_secs: u32,
) -> Result<KeyGenResponse, String> {
    let uid_str = user_id.unwrap_or_default();
    let trimmed_uid = uid_str.trim();
    if trimmed_uid.is_empty() {
        return Err(
            "Compatibility failure: OpenPGP v4 (RSA-4096) keys require a non-empty User ID for Kleopatra / GnuPG import and self-certification."
                .into(),
        );
    }

    let mut rng = VaultRng;
    let created = Timestamp::from_secs(now_secs);
    let pw = Password::from(passphrase.as_str());

    // 1. Generate OpenPGP v4 Primary Key (RSA-4096) for Certification + Signing
    //    Protected with S2K Usage 254 (CFB + SHA-1 checksum), AES-256, Iterated & Salted S2K (SHA-256, count=224).
    let (pub_params, sec_params_raw) = KeyType::Rsa(4096)
        .generate(&mut rng)
        .map_err(|e| format!("RSA-4096 primary key generation failed: {e}"))?;
    let primary_pub_inner = PubKeyInner::new(
        KeyVersion::V4,
        KeyType::Rsa(4096).to_alg(),
        created,
        None,
        pub_params,
    )
    .map_err(|e| format!("Primary key header creation failed: {e}"))?;
    let primary_pub_pkt = PacketPublicKey::from_inner(primary_pub_inner)
        .map_err(|e| format!("Primary public key packet failed: {e}"))?;
    let primary_s2k = S2kParams::new_default(&mut rng, KeyVersion::V4);
    let primary_sec_params = match &sec_params_raw {
        SecretParams::Plain(plain) => SecretParams::Encrypted(
            plain
                .encrypt(
                    passphrase.as_bytes(),
                    primary_s2k,
                    &primary_pub_pkt,
                    Some(Tag::SecretKey),
                )
                .map_err(|e| format!("Primary key encryption failed: {e}"))?,
        ),
        other => other.clone(),
    };
    let primary_key = PacketSecretKey::new(primary_pub_pkt.clone(), primary_sec_params)
        .map_err(|e| format!("Primary secret key packet failed: {e}"))?;

    // 2. Primary User ID + v4 CertPositive self-signature carrying KeyFlags (Certify + Sign) and preferences
    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);

    let mut features = Features::new();
    features.set_seipd_v1(true);

    let uid = UserId::from_str(PacketHeaderVersion::New, trimmed_uid)
        .map_err(|e| format!("Invalid User ID: {e}"))?;
    let mut uid_cfg = SignatureConfig::v4(
        SignatureType::CertPositive,
        primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    uid_cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::Features(features))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            [
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ]
            .into_iter()
            .collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            [
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha384,
            ]
            .into_iter()
            .collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
            [CompressionAlgorithm::Uncompressed].into_iter().collect(),
        ))
        .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::IsPrimary(true))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    uid_cfg.unhashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerKeyId(primary_key.legacy_key_id()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];

    let primary_pub_pkt = primary_key.public_key();
    let uid_sig = uid_cfg
        .sign_certification(&primary_key, &primary_pub_pkt, &pw, uid.tag(), &uid)
        .map_err(|e| format!("User ID certification signature failed: {e}"))?;
    let users = vec![SignedUser::new(uid, vec![uid_sig])];

    // 3. Generate OpenPGP v4 Encryption Subkey (RSA-4096) + v4 SubkeyBinding Signature
    let (sub_pub_params, sub_sec_raw) = KeyType::Rsa(4096)
        .generate(&mut rng)
        .map_err(|e| format!("RSA-4096 encryption subkey generation failed: {e}"))?;
    let sub_pub_inner = PubKeyInner::new(
        KeyVersion::V4,
        KeyType::Rsa(4096).to_alg(),
        created,
        None,
        sub_pub_params,
    )
    .map_err(|e| format!("Subkey header creation failed: {e}"))?;
    let sub_pub_pkt = PacketPublicSubkey::from_inner(sub_pub_inner)
        .map_err(|e| format!("Subkey public packet failed: {e}"))?;
    let sub_s2k = S2kParams::new_default(&mut rng, KeyVersion::V4);
    let sub_sec_params = match &sub_sec_raw {
        SecretParams::Plain(plain) => SecretParams::Encrypted(
            plain
                .encrypt(
                    passphrase.as_bytes(),
                    sub_s2k,
                    &sub_pub_pkt,
                    Some(Tag::SecretSubkey),
                )
                .map_err(|e| format!("Subkey encryption failed: {e}"))?,
        ),
        other => other.clone(),
    };
    let sub_key = PacketSecretSubkey::new(sub_pub_pkt, sub_sec_params)
        .map_err(|e| format!("Subkey secret packet failed: {e}"))?;

    let mut sub_flags = KeyFlags::default();
    sub_flags.set_encrypt_comms(true);
    sub_flags.set_encrypt_storage(true);

    let mut sub_cfg = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    sub_cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
        Subpacket::regular(SubpacketData::KeyFlags(sub_flags))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    sub_cfg.unhashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerKeyId(primary_key.legacy_key_id()))
            .map_err(|e| format!("Subpacket error: {e}"))?,
    ];
    let sub_binding = sub_cfg
        .sign_subkey_binding(&primary_key, &primary_pub_pkt, &pw, &sub_key.public_key())
        .map_err(|e| format!("Subkey binding signature failed: {e}"))?;

    let details = SignedKeyDetails::new(vec![], vec![], users, vec![]);
    let secret_key = SignedSecretKey::new(
        primary_key,
        details,
        vec![],
        vec![SignedSecretSubKey::new(sub_key, vec![sub_binding])],
    );

    // Verify self-signatures and subkey bindings immediately
    secret_key
        .verify_bindings()
        .map_err(|e| format!("Self-signature verification failed: {e}"))?;

    let public_key = secret_key.to_public_key();
    let armor_opts = ArmorOptions::default(); // headers: None (no Version/Comment)

    let public_key_armored = public_key
        .to_armored_string(armor_opts.clone())
        .map_err(|e| format!("Public key export failed: {e}"))?;
    let secret_key_armored = Zeroizing::new(
        secret_key
            .to_armored_string(armor_opts)
            .map_err(|e| format!("Secret key export failed: {e}"))?,
    );

    let summary = store.upsert_secret(secret_key, true);

    Ok(KeyGenResponse {
        summary,
        public_key_armored,
        secret_key_armored: secret_key_armored.to_string(),
        profile: "Compatibility — OpenPGP v4 (RSA-4096 + RSA-4096, S2K Iterated+Salted SHA-256 + AES-256-CFB)".into(),
    })
}

pub fn import_keys(store: &mut SessionStore, req: ImportKeyRequest) -> Result<ImportKeyResponse, String> {
    check_base64_input_size(req.data_b64.len(), "Key import")?;
    let raw_input = Zeroizing::new(
        B64.decode(req.data_b64.as_bytes())
            .map_err(|e| format!("Invalid Base64 input: {e}"))?,
    );
    check_input_size(raw_input.len(), "Key import")?;

    let binary_bytes = if is_ascii_armored(&raw_input) {
        Zeroizing::new(dearmor_to_bytes(&raw_input)?)
    } else {
        raw_input
    };

    let _tags = inspect_raw_packets(&binary_bytes)?;

    let mut imported = Vec::new();

    // Try secret keys first
    if let Ok(iter) = SignedSecretKey::from_bytes_many(Cursor::new(binary_bytes.as_slice())) {
        let mut count = 0usize;
        for item in iter {
            if let Ok(sk) = item {
                count += 1;
                if count > MAX_KEYS_PER_IMPORT {
                    return Err(format!(
                        "Key import exceeds the limit of {MAX_KEYS_PER_IMPORT} keys."
                    ));
                }
                check_secret_key_s2k(&sk)?;
                sk.verify_bindings()
                    .map_err(|e| format!("Invalid key self-signature: {e}"))?;
                imported.push(store.upsert_secret(sk, false));
            }
        }
    }

    // If no secret keys parsed, try public keys
    if imported.is_empty() {
        let iter = SignedPublicKey::from_bytes_many(Cursor::new(binary_bytes.as_slice()))
            .map_err(|e| format!("Failed to parse key: {e}"))?;
        let mut count = 0usize;
        for item in iter {
            let pk = item.map_err(|e| format!("Invalid public key: {e}"))?;
            count += 1;
            if count > MAX_KEYS_PER_IMPORT {
                return Err(format!(
                    "Key import exceeds the limit of {MAX_KEYS_PER_IMPORT} keys."
                ));
            }
            pk.verify_bindings()
                .map_err(|e| format!("Invalid key self-signature: {e}"))?;
            imported.push(store.upsert_public(pk, false));
        }
    }

    if imported.is_empty() {
        return Err("No valid OpenPGP keys found in input.".into());
    }

    Ok(ImportKeyResponse { imported })
}

pub fn encrypt_message(store: &SessionStore, req: EncryptRequest) -> Result<EncryptResponse, String> {
    check_base64_input_size(req.plaintext_b64.len(), "Plaintext")?;
    let plaintext = Zeroizing::new(
        B64.decode(req.plaintext_b64.as_bytes())
            .map_err(|e| format!("Invalid Base64 plaintext input: {e}"))?,
    );
    check_input_size(plaintext.len(), "Plaintext")?;

    if req.recipient_fingerprints.is_empty() {
        return Err("At least one recipient key must be selected.".into());
    }
    if req.recipient_fingerprints.len() > MAX_RECIPIENTS {
        return Err(format!(
            "Too many recipients (max {MAX_RECIPIENTS})."
        ));
    }

    let profile = req.profile.as_deref().unwrap_or("rfc9580");
    if profile != "rfc9580" && profile != "compat_seipd_v1" {
        return Err(format!("Unknown encryption profile: {profile}"));
    }

    let mut recipients = Vec::with_capacity(req.recipient_fingerprints.len());
    for fp in &req.recipient_fingerprints {
        let norm = fp.trim().to_uppercase();
        let stored = store
            .public_keys
            .iter()
            .find(|k| k.fingerprint == norm)
            .ok_or_else(|| format!("Recipient key {norm} was not found in the session."))?;
        let enc_key = select_encryption_target(&stored.key, req.now_secs)?;
        recipients.push(enc_key);
    }

    // Optional signing key setup
    let sign_pw_zero = Zeroizing::new(req.sign_passphrase.unwrap_or_default());
    let signer_opt: Option<&dyn SigningKey> = if let Some(ref sfp) = req.sign_fingerprint {
        let norm = sfp.trim().to_uppercase();
        if norm.is_empty() {
            None
        } else {
            let stored = store
                .secret_keys
                .iter()
                .find(|k| k.fingerprint == norm)
                .ok_or_else(|| format!("Signing key {norm} was not found in the session."))?;
            check_secret_key_s2k(&stored.key)?;
            let signing_key: &dyn SigningKey = match select_signing_target(&stored.key, req.now_secs)? {
                SignTarget::Primary(k) => k,
                SignTarget::Subkey(k) => k,
            };
            Some(signing_key)
        }
    } else {
        None
    };

    let mut rng = VaultRng;

    // Empty filename ("") and timestamp 0 are enforced by rPGP's LiteralDataHeader::new(DataMode::Binary)
    let raw_output = if profile == "rfc9580" {
        let mut builder = MessageBuilder::from_bytes("", plaintext.as_slice().to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::C4KiB,
        );
        for enc_key in recipients {
            let res = match enc_key {
                EncTarget::Primary(k) => builder.encrypt_to_key_anonymous(&mut rng, k),
                EncTarget::Subkey(k) => builder.encrypt_to_key_anonymous(&mut rng, k),
            };
            res.map_err(|e| {
                format!(
                    "RFC 9580 encryption (v2-SEIPD/v6-PKESK) failed for recipient (no silent fallback): {e}"
                )
            })?;
        }
        if let Some(signing_key) = signer_opt {
            let subpackets = build_subpackets(signing_key, req.now_secs)?;
            let pw = Password::from(sign_pw_zero.as_str());
            builder.sign_with_subpackets(signing_key, pw, HashAlgorithm::Sha256, subpackets);
        }
        builder
            .to_vec(&mut rng)
            .map_err(|e| format!("Encryption (RFC 9580) failed: {e}"))?
    } else {
        let mut builder = MessageBuilder::from_bytes("", plaintext.as_slice().to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for enc_key in recipients {
            let res = match enc_key {
                EncTarget::Primary(k) => builder.encrypt_to_key_anonymous(&mut rng, k),
                EncTarget::Subkey(k) => builder.encrypt_to_key_anonymous(&mut rng, k),
            };
            res.map_err(|e| {
                format!(
                    "Compatibility encryption (v1-SEIPD/v3-PKESK) failed: {e}"
                )
            })?;
        }
        if let Some(signing_key) = signer_opt {
            let subpackets = build_subpackets(signing_key, req.now_secs)?;
            let pw = Password::from(sign_pw_zero.as_str());
            builder.sign_with_subpackets(signing_key, pw, HashAlgorithm::Sha256, subpackets);
        }
        builder
            .to_vec(&mut rng)
            .map_err(|e| format!("Encryption (v1-SEIPD) failed: {e}"))?
    };

    let output_armored = if req.armor {
        let mut out = Vec::new();
        pgp::armor::write(
            &RawPacketSlice(&raw_output),
            pgp::armor::BlockType::Message,
            &mut out,
            None, // NO Version / Comment headers!
            true,
        )
        .map_err(|e| format!("ASCII Armor encoding failed: {e}"))?;
        Some(String::from_utf8(out).map_err(|e| format!("UTF-8 error: {e}"))?)
    } else {
        None
    };

    // Directly audit serialized packets before returning!
    let packet_audit = audit_message_packets(&raw_output, output_armored.as_deref())?;
    if !packet_audit.all_pkesk_anonymous {
        return Err("Internal security error: non-anonymous PKESK detected.".into());
    }
    if packet_audit.armor_has_version_or_comment {
        return Err("Internal security error: ASCII Armor contains Version or Comment header.".into());
    }
    if packet_audit.has_unauthenticated_sed {
        return Err("Internal security error: unauthenticated SED packet produced.".into());
    }

    let output_b64 = if let Some(ref arm) = output_armored {
        B64.encode(arm.as_bytes())
    } else {
        B64.encode(&raw_output)
    };

    Ok(EncryptResponse {
        output_b64,
        output_armored,
        profile_used: if profile == "rfc9580" {
            "RFC 9580 (v2-SEIPD + AES-256 + AEAD-OCB + anonymous v6-PKESK)".into()
        } else {
            "Compatibility (v1-SEIPD + MDC + AES-256 + anonymous v3-PKESK)".into()
        },
        packet_audit,
    })
}

struct RawPacketSlice<'a>(&'a [u8]);

impl pgp::ser::Serialize for RawPacketSlice<'_> {
    fn to_writer<W: std::io::Write + ?Sized>(&self, writer: &mut W) -> pgp::errors::Result<()> {
        writer.write_all(self.0)?;
        Ok(())
    }
    fn write_len(&self) -> usize {
        self.0.len()
    }
}

pub fn decrypt_message(store: &SessionStore, req: DecryptRequest) -> Result<DecryptResponse, String> {
    check_base64_input_size(req.input_b64.len(), "Encrypted message")?;
    let raw_input = B64
        .decode(req.input_b64.as_bytes())
        .map_err(|e| format!("Invalid Base64 input: {e}"))?;
    check_input_size(raw_input.len(), "Encrypted message")?;

    let binary_bytes = if is_ascii_armored(&raw_input) {
        dearmor_to_bytes(&raw_input)?
    } else {
        raw_input
    };

    let _tags = inspect_raw_packets(&binary_bytes)?;
    let audit = audit_message_packets(&binary_bytes, None)?;

    if audit.has_unauthenticated_sed {
        return Err(
            "Rejected: unauthenticated message without integrity protection (SED / Tag 9).".into(),
        );
    }

    if audit.seipd_count != 1 {
        return Err(format!(
            "Rejected: expected exactly 1 integrity-protected SEIPD packet, found {}.",
            audit.seipd_count
        ));
    }

    let seipd_version = audit.seipd_version.ok_or_else(|| {
        "Rejected: no integrity-protected SEIPD message found.".to_string()
    })?;

    if seipd_version == 1 && !req.allow_legacy_seipd_v1 {
        return Err(
            "Rejected: message uses legacy v1-SEIPD+MDC format. Explicitly enable the v1 read profile to decrypt it."
                .into(),
        );
    }

    if store.secret_keys.is_empty() {
        return Err("No secret key is loaded in the session.".into());
    }

    let mut sk_refs: Vec<&SignedSecretKey> = Vec::with_capacity(store.secret_keys.len());
    for stored in &store.secret_keys {
        check_secret_key_s2k(&stored.key)?;
        sk_refs.push(&stored.key);
    }

    // Enforce conservative upper bound on anonymous and total PKESK decryption attempts across ALL
    // primary keys + subkeys that rPGP's `TheRing::find_session_key` will consider.
    let budget = estimate_pkesk_decrypt_budget(&binary_bytes, &sk_refs)?;
    if budget.worst_case_anon_attempts > MAX_ANON_DECRYPT_ATTEMPTS {
        return Err(format!(
            "Anonymous decryption attempts exceed limit ({} > {}: {} anonymous PKESK × {} candidate keys including subkeys). Reduce loaded keys or inspect the message.",
            budget.worst_case_anon_attempts,
            MAX_ANON_DECRYPT_ATTEMPTS,
            budget.anon_pkesk_count,
            budget.candidate_keys_per_anon_pkesk
        ));
    }
    if budget.worst_case_total_attempts > MAX_TOTAL_DECRYPT_ATTEMPTS {
        return Err(format!(
            "Total PKESK decryption attempts exceed limit ({} > {}).",
            budget.worst_case_total_attempts, MAX_TOTAL_DECRYPT_ATTEMPTS
        ));
    }

    let passphrase = Zeroizing::new(req.passphrase.unwrap_or_default());
    let pw = Password::from(passphrase.as_str());

    let msg = Message::from_bytes(Cursor::new(binary_bytes.as_slice()))
        .map_err(|e| format!("Failed to parse message: {e}"))?;

    let mut decrypted = msg
        .decrypt_with_keys(vec![&pw], sk_refs)
        .map_err(|e| format!("Decryption failed (key, passphrase, or format): {e}"))?;

    let mut was_compressed = false;
    if matches!(decrypted, Message::Compressed { .. }) {
        was_compressed = true;
        decrypted = decrypted
            .decompress()
            .map_err(|e| format!("Decompression failed: {e}"))?;
        if matches!(decrypted, Message::Compressed { .. }) {
            return Err("Rejected: nested compressed packets are not allowed.".into());
        }
    }

    // Read ALL plaintext bytes first so AEAD / MDC integrity verification runs to completion!
    // If integrity fails or message is truncated, `read_all_with_limits` returns Err and zeroizes the buffer.
    let plaintext = read_all_with_limits(&mut decrypted, binary_bytes.len(), was_compressed)?;

    let (literal_filename, literal_timestamp) = match decrypted.literal_data_header() {
        Some(hdr) => (
            String::from_utf8_lossy(hdr.file_name()).into_owned(),
            hdr.created().as_secs(),
        ),
        None => (String::new(), 0),
    };

    // Inspect & verify inline signatures (if any) against validated, eligible verifying keys
    let signature = verify_inline_signatures(store, &decrypted, req.now_secs);

    Ok(DecryptResponse {
        plaintext_b64: B64.encode(plaintext.as_slice()),
        seipd_version,
        was_compressed,
        literal_filename,
        literal_timestamp,
        signature,
    })
}

fn verify_inline_signatures(store: &SessionStore, msg: &Message<'_>, now_secs: u32) -> SignatureInfo {
    if !matches!(msg, Message::Signed { .. }) {
        return SignatureInfo {
            status: "none".into(),
            signer_fingerprint: None,
            signer_user_ids: Vec::new(),
            signer_identity_confirmed: false,
            created_at: None,
        };
    }

    for pk in &store.public_keys {
        // Only consider validated, non-revoked, non-expired signing-capable keys/subkeys
        // with explicit Sign Key Flags and valid subkey bindings/backsignatures.
        let targets = select_verifying_keys(&pk.key, now_secs);
        if targets.is_empty() {
            continue;
        }
        let verifiers: Vec<&dyn VerifyingKey> = targets
            .iter()
            .map(|t| match t {
                VerifyTarget::Primary(k) => *k as &dyn VerifyingKey,
                VerifyTarget::Subkey(k) => *k as &dyn VerifyingKey,
            })
            .collect();
        if let Ok(results) = msg.verify_nested(&verifiers) {
            for res in results {
                if let pgp::composed::VerificationResult::Valid(sig) = res {
                    if is_signature_active(&sig, now_secs) {
                        return SignatureInfo {
                            status: "valid".into(),
                            signer_fingerprint: Some(pk.fingerprint.clone()),
                            signer_user_ids: pk.user_ids.clone(),
                            signer_identity_confirmed: pk.identity_confirmed,
                            created_at: sig.created().map(|t| t.as_secs()),
                        };
                    }
                }
            }
        }
    }

    // Signature present but did not validate against any eligible loaded key
    SignatureInfo {
        status: if store.public_keys.is_empty() {
            "unknown_signer".into()
        } else {
            "invalid".into()
        },
        signer_fingerprint: None,
        signer_user_ids: Vec::new(),
        signer_identity_confirmed: false,
        created_at: None,
    }
}

pub fn sign_detached(
    store: &SessionStore,
    req: SignDetachedRequest,
) -> Result<SignDetachedResponse, String> {
    check_base64_input_size(req.data_b64.len(), "Data to sign")?;
    let data = Zeroizing::new(
        B64.decode(req.data_b64.as_bytes())
            .map_err(|e| format!("Invalid Base64 data: {e}"))?,
    );
    check_input_size(data.len(), "Data to sign")?;

    let norm = req.sign_fingerprint.trim().to_uppercase();
    let stored = store
        .secret_keys
        .iter()
        .find(|k| k.fingerprint == norm)
        .ok_or_else(|| format!("Signing key {norm} was not found in the session."))?;
    check_secret_key_s2k(&stored.key)?;

    let passphrase = Zeroizing::new(req.passphrase);
    let pw = Password::from(passphrase.as_str());
    let mut rng = VaultRng;

    // Select validated, non-revoked, non-expired signing key with explicit Sign flag
    let target = select_signing_target(&stored.key, req.now_secs)?;
    let sig = match target {
        SignTarget::Primary(k) => {
            let subpackets = build_subpackets(k, req.now_secs)?;
            DetachedSignature::sign_binary_data_with_subpackets(
                &mut rng,
                k,
                &pw,
                HashAlgorithm::Sha256,
                Cursor::new(data.as_slice()),
                subpackets,
            )
        }
        SignTarget::Subkey(k) => {
            let subpackets = build_subpackets(k, req.now_secs)?;
            DetachedSignature::sign_binary_data_with_subpackets(
                &mut rng,
                k,
                &pw,
                HashAlgorithm::Sha256,
                Cursor::new(data.as_slice()),
                subpackets,
            )
        }
    }
    .map_err(|e| format!("Signing failed (passphrase or key): {e}"))?;

    let signature_armored = if req.armor {
        let arm = sig
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("ASCII Armor encoding failed: {e}"))?;
        Some(arm)
    } else {
        None
    };

    let signature_b64 = if let Some(ref arm) = signature_armored {
        B64.encode(arm.as_bytes())
    } else {
        let mut raw = Vec::new();
        pgp::ser::Serialize::to_writer(&sig, &mut raw)
            .map_err(|e| format!("Signature serialization failed: {e}"))?;
        B64.encode(&raw)
    };

    Ok(SignDetachedResponse {
        signature_b64,
        signature_armored,
        signer_fingerprint: stored.fingerprint.clone(),
    })
}

pub fn verify_detached(
    store: &SessionStore,
    req: VerifyDetachedRequest,
) -> Result<SignatureInfo, String> {
    check_base64_input_size(req.data_b64.len(), "Data to verify")?;
    let data = Zeroizing::new(
        B64.decode(req.data_b64.as_bytes())
            .map_err(|e| format!("Invalid Base64 data: {e}"))?,
    );
    check_input_size(data.len(), "Data to verify")?;

    check_base64_input_size(req.signature_b64.len(), "Signature")?;
    let sig_raw = B64
        .decode(req.signature_b64.as_bytes())
        .map_err(|e| format!("Invalid Base64 signature: {e}"))?;
    check_input_size(sig_raw.len(), "Signature")?;

    let sig_bytes = if is_ascii_armored(&sig_raw) {
        dearmor_to_bytes(&sig_raw)?
    } else {
        sig_raw
    };
    let _tags = inspect_raw_packets(&sig_bytes)?;

    let sig = DetachedSignature::from_bytes(Cursor::new(sig_bytes.as_slice()))
        .map_err(|e| format!("Invalid detached signature: {e}"))?;

    if store.public_keys.is_empty() {
        return Ok(SignatureInfo {
            status: "unknown_signer".into(),
            signer_fingerprint: None,
            signer_user_ids: Vec::new(),
            signer_identity_confirmed: false,
            created_at: sig.signature.created().map(|t| t.as_secs()),
        });
    }

    if is_signature_active(&sig.signature, req.now_secs) {
        for pk in &store.public_keys {
            for target in select_verifying_keys(&pk.key, req.now_secs) {
                let verified = match target {
                    VerifyTarget::Primary(k) => sig.verify(k, data.as_slice()).is_ok(),
                    VerifyTarget::Subkey(k) => sig.verify(k, data.as_slice()).is_ok(),
                };
                if verified {
                    return Ok(SignatureInfo {
                        status: "valid".into(),
                        signer_fingerprint: Some(pk.fingerprint.clone()),
                        signer_user_ids: pk.user_ids.clone(),
                        signer_identity_confirmed: pk.identity_confirmed,
                        created_at: sig.signature.created().map(|t| t.as_secs()),
                    });
                }
            }
        }
    }

    Ok(SignatureInfo {
        status: "invalid".into(),
        signer_fingerprint: None,
        signer_user_ids: Vec::new(),
        signer_identity_confirmed: false,
        created_at: sig.signature.created().map(|t| t.as_secs()),
    })
}
