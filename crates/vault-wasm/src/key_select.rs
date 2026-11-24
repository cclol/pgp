use pgp::composed::{SignedKeyDetails, SignedPublicKey, SignedSecretKey};
use pgp::packet::{
    KeyFlags, PacketTrait, PublicKey as PacketPublicKey, PublicSubkey as PacketPublicSubkey,
    SecretKey as PacketSecretKey, SecretSubkey as PacketSecretSubkey, Signature, SignatureType,
    SubpacketData,
};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, VerifyingKey};

pub enum EncTarget<'a> {
    Primary(&'a PacketPublicKey),
    Subkey(&'a PacketPublicSubkey),
}

pub enum SignTarget<'a> {
    Primary(&'a PacketSecretKey),
    Subkey(&'a PacketSecretSubkey),
}

pub enum VerifyTarget<'a> {
    Primary(&'a PacketPublicKey),
    Subkey(&'a PacketPublicSubkey),
}

/// Extracts explicit `KeyFlags` from a signature's hashed subpackets.
/// Returns `None` if no `KeyFlags` subpacket is present (e.g. legacy keys without Key Flags).
fn explicit_key_flags(sig: &Signature) -> Option<KeyFlags> {
    let cfg = sig.config()?;
    for sp in cfg.hashed_subpackets() {
        if let SubpacketData::KeyFlags(flags) = &sp.data {
            return Some(flags.clone());
        }
    }
    None
}

fn sig_created_secs(sig: &Signature) -> u32 {
    sig.created().map(|t| t.as_secs()).unwrap_or(0)
}

pub fn is_signature_active(sig: &Signature, now_secs: u32) -> bool {
    let Some(created) = sig.created() else {
        return false;
    };
    let created_s = created.as_secs();
    if created_s > now_secs {
        return false;
    }
    if let Some(exp) = sig.signature_expiration_time() {
        let exp_s = exp.as_secs();
        if exp_s > 0 && now_secs >= created_s.saturating_add(exp_s) {
            return false;
        }
    }
    true
}

fn is_key_expired(key_created_secs: u32, sig: &Signature, now_secs: u32) -> bool {
    if let Some(exp) = sig.key_expiration_time() {
        let exp_s = exp.as_secs();
        if exp_s > 0 && now_secs >= key_created_secs.saturating_add(exp_s) {
            return true;
        }
    }
    false
}

struct PrimaryValidation {
    flags: Option<KeyFlags>,
}

/// Validates a primary key's revocations, self-signatures, and expiration at `now_secs`.
fn validate_primary<V>(
    primary: &V,
    details: &SignedKeyDetails,
    now_secs: u32,
) -> Result<PrimaryValidation, String>
where
    V: KeyDetails + VerifyingKey + Serialize,
{
    let fp = hex::encode_upper(primary.fingerprint().as_bytes());
    let created_secs = primary.created_at().as_secs();
    if created_secs > now_secs {
        return Err(format!(
            "Key {fp} has a creation timestamp in the future."
        ));
    }

    // 1. Check primary key revocation signatures (both in revocation_signatures and direct_signatures)
    for sig in details
        .revocation_signatures
        .iter()
        .chain(details.direct_signatures.iter())
    {
        if sig.typ() == Some(SignatureType::KeyRevocation) && sig.verify_key(primary).is_ok() {
            return Err(format!("Key {fp} has been revoked."));
        }
    }

    // 2. Find latest valid direct-key self-signature
    let mut best_direct: Option<&Signature> = None;
    for sig in &details.direct_signatures {
        if sig.typ() != Some(SignatureType::Key) {
            continue;
        }
        if !is_signature_active(sig, now_secs) {
            continue;
        }
        if sig.verify_key(primary).is_ok()
            && best_direct
                .map(|b| sig_created_secs(sig) >= sig_created_secs(b))
                .unwrap_or(true)
        {
            best_direct = Some(sig);
        }
    }

    // 3. Find latest valid non-revoked User-ID self-certification (common on v4 keys)
    let mut best_uid_sig: Option<&Signature> = None;
    for user in &details.users {
        let mut user_revoked = false;
        let mut latest_cert: Option<&Signature> = None;
        let mut latest_rev_ts = 0u32;

        for sig in &user.signatures {
            if sig.typ() == Some(SignatureType::CertRevocation)
                && sig.verify_certification(primary, user.id.tag(), &user.id).is_ok()
            {
                let ts = sig_created_secs(sig);
                if ts >= latest_rev_ts {
                    latest_rev_ts = ts;
                    user_revoked = true;
                }
            }
        }

        for sig in &user.signatures {
            let is_cert = matches!(
                sig.typ(),
                Some(
                    SignatureType::CertGeneric
                        | SignatureType::CertPersona
                        | SignatureType::CertCasual
                        | SignatureType::CertPositive
                )
            );
            if !is_cert || !is_signature_active(sig, now_secs) {
                continue;
            }
            if sig.verify_certification(primary, user.id.tag(), &user.id).is_ok()
                && latest_cert
                    .map(|b| sig_created_secs(sig) >= sig_created_secs(b))
                    .unwrap_or(true)
            {
                latest_cert = Some(sig);
            }
        }

        if let Some(cert) = latest_cert {
            if user_revoked && latest_rev_ts >= sig_created_secs(cert) {
                continue;
            }
            if best_uid_sig
                .map(|b| sig_created_secs(cert) >= sig_created_secs(b))
                .unwrap_or(true)
            {
                best_uid_sig = Some(cert);
            }
        }
    }

    let authoritative = match (best_direct, best_uid_sig) {
        (Some(d), Some(u)) => {
            if sig_created_secs(d) >= sig_created_secs(u) {
                d
            } else {
                u
            }
        }
        (Some(d), None) => d,
        (None, Some(u)) => u,
        (None, None) => {
            return Err(format!(
                "Key {fp} has no valid, active self-signature."
            ));
        }
    };

    // 4. Check primary key expiration on authoritative self-signature (and direct signature if present)
    if is_key_expired(created_secs, authoritative, now_secs)
        || best_direct
            .map(|d| is_key_expired(created_secs, d, now_secs))
            .unwrap_or(false)
    {
        return Err(format!("Key {fp} has expired."));
    }

    let flags = explicit_key_flags(authoritative)
        .or_else(|| best_direct.and_then(explicit_key_flags))
        .or_else(|| best_uid_sig.and_then(explicit_key_flags));

    Ok(PrimaryValidation { flags })
}

/// Validates a subkey's binding & revocation signatures and returns its latest active binding signature.
fn validate_subkey_binding<'a, P, S>(
    primary: &P,
    subkey: &S,
    signatures: &'a [Signature],
    now_secs: u32,
) -> Result<&'a Signature, &'static str>
where
    P: KeyDetails + VerifyingKey + Serialize,
    S: KeyDetails + Serialize,
{
    if subkey.created_at().as_secs() > now_secs {
        return Err("creation timestamp in the future");
    }

    // Any valid SubkeyRevocation revokes this subkey
    for sig in signatures {
        if sig.typ() == Some(SignatureType::SubkeyRevocation)
            && sig.verify_subkey_binding(primary, subkey).is_ok()
        {
            return Err("revoked");
        }
    }

    // Select latest cryptographically valid, active SubkeyBinding signature
    let mut best: Option<&Signature> = None;
    for sig in signatures {
        if sig.typ() != Some(SignatureType::SubkeyBinding) {
            continue;
        }
        if !is_signature_active(sig, now_secs) {
            continue;
        }
        if sig.verify_subkey_binding(primary, subkey).is_ok()
            && best
                .map(|b| sig_created_secs(sig) >= sig_created_secs(b))
                .unwrap_or(true)
        {
            best = Some(sig);
        }
    }

    let binding = best.ok_or("no valid binding signature")?;
    if is_key_expired(subkey.created_at().as_secs(), binding, now_secs) {
        return Err("expired");
    }

    Ok(binding)
}

/// Selects a valid, non-revoked, non-expired encryption key with explicit encryption Key Flags
/// (`encrypt_comms` or `encrypt_storage`).
///
/// Legacy keys without an explicit `KeyFlags` subpacket are rejected fail-closed to prevent
/// cross-purpose key misuse.
pub fn select_encryption_target<'a>(
    pk: &'a SignedPublicKey,
    now_secs: u32,
) -> Result<EncTarget<'a>, String> {
    let fp = hex::encode_upper(pk.primary_key.fingerprint().as_bytes());
    let primary_val = validate_primary(&pk.primary_key, &pk.details, now_secs)?;

    let mut reasons: Vec<&'static str> = Vec::new();
    let mut best_subkey: Option<(u32, &'a PacketPublicSubkey)> = None;

    for sub in &pk.public_subkeys {
        if !sub.key.algorithm().can_encrypt() {
            reasons.push("algorithm cannot encrypt");
            continue;
        }
        let binding = match validate_subkey_binding(
            &pk.primary_key,
            &sub.key,
            &sub.signatures,
            now_secs,
        ) {
            Ok(b) => b,
            Err(reason) => {
                reasons.push(reason);
                continue;
            }
        };
        let Some(flags) = explicit_key_flags(binding) else {
            reasons.push("legacy key without explicit Key Flags");
            continue;
        };
        if !(flags.encrypt_comms() || flags.encrypt_storage()) {
            reasons.push("wrong-purpose Key Flags (not enabled for encryption)");
            continue;
        }
        let created = sub.key.created_at().as_secs();
        if best_subkey.map(|(c, _)| created >= c).unwrap_or(true) {
            best_subkey = Some((created, &sub.key));
        }
    }

    if let Some((_, sub)) = best_subkey {
        return Ok(EncTarget::Subkey(sub));
    }

    // Fallback to primary key ONLY if primary algorithm & explicit Key Flags allow encryption
    if pk.primary_key.algorithm().can_encrypt() {
        match primary_val.flags {
            Some(flags) if flags.encrypt_comms() || flags.encrypt_storage() => {
                return Ok(EncTarget::Primary(&pk.primary_key));
            }
            Some(_) => reasons.push("primary key lacks encryption Key Flags"),
            None => reasons.push("primary key lacks explicit Key Flags"),
        }
    }

    reasons.sort_unstable();
    reasons.dedup();
    let detail = if reasons.is_empty() {
        "no encryption-capable key available".to_string()
    } else {
        reasons.join(", ")
    };
    Err(format!(
        "No eligible encryption key found for {fp} ({detail})."
    ))
}

/// Selects a valid, non-revoked, non-expired signing key with explicit `Sign` Key Flag.
/// For signing subkeys, also enforces a valid embedded primary-key binding backsignature.
///
/// Legacy keys without an explicit `KeyFlags` subpacket are rejected fail-closed.
pub fn select_signing_target<'a>(
    sk: &'a SignedSecretKey,
    now_secs: u32,
) -> Result<SignTarget<'a>, String> {
    let fp = hex::encode_upper(sk.primary_key.fingerprint().as_bytes());
    let primary_pub = sk.primary_key.public_key();
    let primary_val = validate_primary(&primary_pub, &sk.details, now_secs)?;

    let mut reasons: Vec<&'static str> = Vec::new();
    let mut best_subkey: Option<(u32, &'a PacketSecretSubkey)> = None;

    for sub in &sk.secret_subkeys {
        if !sub.key.algorithm().can_sign() {
            continue;
        }
        let sub_pub = sub.key.public_key();
        let binding = match validate_subkey_binding(
            &primary_pub,
            &sub_pub,
            &sub.signatures,
            now_secs,
        ) {
            Ok(b) => b,
            Err(reason) => {
                reasons.push(reason);
                continue;
            }
        };
        let Some(flags) = explicit_key_flags(binding) else {
            reasons.push("legacy key without explicit Key Flags");
            continue;
        };
        if !flags.sign() {
            reasons.push("wrong-purpose Key Flags (not enabled for signing)");
            continue;
        }
        // RFC 9580 / RFC 4880: signing-capable subkeys MUST carry a valid embedded backsignature
        let Some(backsig) = binding.embedded_signature() else {
            reasons.push("missing primary-key binding backsignature on signing subkey");
            continue;
        };
        if backsig.typ() != Some(SignatureType::KeyBinding)
            || !is_signature_active(backsig, now_secs)
            || backsig.verify_primary_key_binding(&sub_pub, &primary_pub).is_err()
        {
            reasons.push("invalid or inactive primary-key binding backsignature on signing subkey");
            continue;
        }
        let created = sub.key.created_at().as_secs();
        if best_subkey.map(|(c, _)| created >= c).unwrap_or(true) {
            best_subkey = Some((created, &sub.key));
        }
    }

    if let Some((_, sub)) = best_subkey {
        return Ok(SignTarget::Subkey(sub));
    }

    if sk.primary_key.algorithm().can_sign() {
        match primary_val.flags {
            Some(flags) if flags.sign() => return Ok(SignTarget::Primary(&sk.primary_key)),
            Some(_) => reasons.push("primary key lacks Sign Key Flag"),
            None => reasons.push("primary key lacks explicit Key Flags"),
        }
    }

    reasons.sort_unstable();
    reasons.dedup();
    let detail = if reasons.is_empty() {
        "no signing-capable key available".to_string()
    } else {
        reasons.join(", ")
    };
    Err(format!(
        "No eligible signing key found for {fp} ({detail})."
    ))
}

/// Returns all currently valid, non-revoked, non-expired verifying keys (primary and/or signing subkeys)
/// with explicit `Sign` Key Flags (and valid embedded primary-key binding backsignatures for subkeys).
pub fn select_verifying_keys<'a>(
    pk: &'a SignedPublicKey,
    now_secs: u32,
) -> Vec<VerifyTarget<'a>> {
    let Ok(primary_val) = validate_primary(&pk.primary_key, &pk.details, now_secs) else {
        return Vec::new();
    };

    let mut out: Vec<VerifyTarget<'a>> = Vec::new();

    if pk.primary_key.algorithm().can_sign() {
        if let Some(flags) = primary_val.flags {
            if flags.sign() {
                out.push(VerifyTarget::Primary(&pk.primary_key));
            }
        }
    }

    for sub in &pk.public_subkeys {
        if !sub.key.algorithm().can_sign() {
            continue;
        }
        let Ok(binding) = validate_subkey_binding(
            &pk.primary_key,
            &sub.key,
            &sub.signatures,
            now_secs,
        ) else {
            continue;
        };
        let Some(flags) = explicit_key_flags(binding) else {
            continue;
        };
        if !flags.sign() {
            continue;
        }
        let Some(backsig) = binding.embedded_signature() else {
            continue;
        };
        if backsig.typ() != Some(SignatureType::KeyBinding)
            || !is_signature_active(backsig, now_secs)
            || backsig.verify_primary_key_binding(&sub.key, &pk.primary_key).is_err()
        {
            continue;
        }
        out.push(VerifyTarget::Subkey(&sub.key));
    }

    out
}
