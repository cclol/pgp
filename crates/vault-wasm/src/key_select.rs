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

fn is_signature_active(sig: &Signature, now_secs: u32) -> bool {
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
            "Schlüssel {fp} hat einen Erstellungszeitpunkt in der Zukunft."
        ));
    }

    // 1. Check primary key revocation signatures (both in revocation_signatures and direct_signatures)
    for sig in details
        .revocation_signatures
        .iter()
        .chain(details.direct_signatures.iter())
    {
        if sig.typ() == Some(SignatureType::KeyRevocation) && sig.verify_key(primary).is_ok() {
            return Err(format!("Schlüssel {fp} wurde widerrufen."));
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
                "Schlüssel {fp} besitzt keine gültige, aktive Selbstsignatur."
            ));
        }
    };

    // 4. Check primary key expiration on authoritative self-signature (and direct signature if present)
    if is_key_expired(created_secs, authoritative, now_secs)
        || best_direct
            .map(|d| is_key_expired(created_secs, d, now_secs))
            .unwrap_or(false)
    {
        return Err(format!("Schlüssel {fp} ist abgelaufen."));
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
        return Err("Erstellungszeitpunkt in der Zukunft");
    }

    // Any valid SubkeyRevocation revokes this subkey
    for sig in signatures {
        if sig.typ() == Some(SignatureType::SubkeyRevocation)
            && sig.verify_subkey_binding(primary, subkey).is_ok()
        {
            return Err("widerrufen");
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

    let binding = best.ok_or("keine gültige Bindungssignatur")?;
    if is_key_expired(subkey.created_at().as_secs(), binding, now_secs) {
        return Err("abgelaufen");
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
            reasons.push("Algorithmus nicht verschlüsselungsfähig");
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
            reasons.push("Altschlüssel ohne explizite Key Flags");
            continue;
        };
        if !(flags.encrypt_comms() || flags.encrypt_storage()) {
            reasons.push("zweckfremde Key Flags (keine Verschlüsselungs-Freigabe)");
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
            Some(_) => reasons.push("Primärschlüssel ohne Verschlüsselungs-Key-Flags"),
            None => reasons.push("Primärschlüssel ohne explizite Key Flags"),
        }
    }

    reasons.sort_unstable();
    reasons.dedup();
    let detail = if reasons.is_empty() {
        "kein verschlüsselungsfähiger Schlüssel vorhanden".to_string()
    } else {
        reasons.join(", ")
    };
    Err(format!(
        "Kein zulässiger Verschlüsselungsschlüssel für {fp} gefunden ({detail})."
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
            reasons.push("Altschlüssel ohne explizite Key Flags");
            continue;
        };
        if !flags.sign() {
            reasons.push("zweckfremde Key Flags (keine Signatur-Freigabe)");
            continue;
        }
        // RFC 9580 / RFC 4880: signing-capable subkeys MUST carry a valid embedded backsignature
        let Some(backsig) = binding.embedded_signature() else {
            reasons.push("fehlende Rücksignatur (Primary Key Binding) am Signatur-Subkey");
            continue;
        };
        if backsig.verify_primary_key_binding(&sub_pub, &primary_pub).is_err() {
            reasons.push("ungültige Rücksignatur am Signatur-Subkey");
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
            Some(_) => reasons.push("Primärschlüssel ohne Signatur-Key-Flag"),
            None => reasons.push("Primärschlüssel ohne explizite Key Flags"),
        }
    }

    reasons.sort_unstable();
    reasons.dedup();
    let detail = if reasons.is_empty() {
        "kein signierfähiger Schlüssel vorhanden".to_string()
    } else {
        reasons.join(", ")
    };
    Err(format!(
        "Kein zulässiger Signaturschlüssel für {fp} gefunden ({detail})."
    ))
}
