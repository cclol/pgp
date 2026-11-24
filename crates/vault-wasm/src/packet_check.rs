use pgp::composed::SignedSecretKey;
use pgp::packet::{Packet, PacketParser, PublicKeyEncryptedSessionKey};
use pgp::types::KeyId;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PkeskBudget {
    pub anon_pkesk_count: usize,
    pub total_pkesk_count: usize,
    pub candidate_keys_per_anon_pkesk: usize,
    pub worst_case_anon_attempts: usize,
    pub worst_case_total_attempts: usize,
}

/// Computes the exact conservative upper bound of asymmetric decryption / S2K unlock attempts
/// that rPGP's `TheRing::find_session_key` can execute across all PKESK packets and all
/// primary + subkeys in `secret_keys`.
///
/// For every anonymous PKESK (v3 wildcard KeyID or v6 omitted fingerprint), rPGP's
/// `match_identity` matches every primary key and every subkey in every loaded secret key bundle.
pub fn estimate_pkesk_decrypt_budget(
    raw_bytes: &[u8],
    secret_keys: &[&SignedSecretKey],
) -> Result<PkeskBudget, String> {
    let mut anon_pkesk_count = 0usize;
    let mut total_pkesk_count = 0usize;
    let mut worst_case_anon_attempts = 0usize;
    let mut worst_case_total_attempts = 0usize;

    let candidate_keys_per_anon_pkesk: usize = secret_keys
        .iter()
        .map(|sk| 1usize.saturating_add(sk.secret_subkeys.len()))
        .fold(0usize, |acc, n| acc.saturating_add(n));

    for pkt_res in PacketParser::new(raw_bytes) {
        let pkt = pkt_res.map_err(|e| format!("PKESK budget check failed: {e}"))?;
        if let Packet::PublicKeyEncryptedSessionKey(pkesk) = pkt {
            total_pkesk_count = total_pkesk_count.saturating_add(1);
            let is_anon = match &pkesk {
                PublicKeyEncryptedSessionKey::V3 { id, .. } => id.is_wildcard(),
                PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => fingerprint.is_none(),
                _ => false,
            };
            if is_anon {
                anon_pkesk_count = anon_pkesk_count.saturating_add(1);
            }

            let mut matched_for_pkt = 0usize;
            for sk in secret_keys {
                if pkesk.match_identity(&sk.primary_key.public_key()) {
                    matched_for_pkt = matched_for_pkt.saturating_add(1);
                }
                for sub in &sk.secret_subkeys {
                    if pkesk.match_identity(&sub.key.public_key()) {
                        matched_for_pkt = matched_for_pkt.saturating_add(1);
                    }
                }
            }

            worst_case_total_attempts = worst_case_total_attempts.saturating_add(matched_for_pkt);
            if is_anon {
                worst_case_anon_attempts = worst_case_anon_attempts.saturating_add(matched_for_pkt);
            }
        }
    }

    Ok(PkeskBudget {
        anon_pkesk_count,
        total_pkesk_count,
        candidate_keys_per_anon_pkesk,
        worst_case_anon_attempts,
        worst_case_total_attempts,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PacketAudit {
    pub pkesk_count: usize,
    pub all_pkesk_anonymous: bool,
    pub pkesk_versions: Vec<u8>,
    pub seipd_count: usize,
    pub seipd_version: Option<u8>,
    pub has_unauthenticated_sed: bool,
    pub armor_has_version_or_comment: bool,
}

/// Checks an ASCII-armored block for forbidden Version: or Comment: headers.
pub fn armor_has_forbidden_headers(armored: &str) -> bool {
    for line in armored.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // End of armor header block
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("version:") || lower.starts_with("comment:") {
            return true;
        }
    }
    false
}

/// Inspects raw OpenPGP message bytes and verifies metadata/security invariants.
pub fn audit_message_packets(raw_bytes: &[u8], armored_text: Option<&str>) -> Result<PacketAudit, String> {
    let mut pkesk_count = 0usize;
    let mut all_pkesk_anonymous = true;
    let mut pkesk_versions = Vec::new();
    let mut seipd_count = 0usize;
    let mut seipd_version = None;
    let mut has_unauthenticated_sed = false;

    for pkt_res in PacketParser::new(raw_bytes) {
        let pkt = pkt_res.map_err(|e| format!("Packet audit failed: {e}"))?;
        match pkt {
            Packet::PublicKeyEncryptedSessionKey(pkesk) => {
                pkesk_count += 1;
                match pkesk {
                    PublicKeyEncryptedSessionKey::V3 { id, .. } => {
                        pkesk_versions.push(3);
                        if id != KeyId::WILDCARD {
                            all_pkesk_anonymous = false;
                        }
                    }
                    PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => {
                        pkesk_versions.push(6);
                        if fingerprint.is_some() {
                            all_pkesk_anonymous = false;
                        }
                    }
                    _ => {
                        all_pkesk_anonymous = false;
                    }
                }
            }
            Packet::SymEncryptedProtectedData(seipd) => {
                seipd_count += 1;
                if seipd_version.is_none() {
                    seipd_version = Some(seipd.version() as u8);
                }
            }
            Packet::SymEncryptedData(_) => {
                has_unauthenticated_sed = true;
            }
            _ => {}
        }
    }

    let armor_has_version_or_comment = armored_text.map(armor_has_forbidden_headers).unwrap_or(false);

    Ok(PacketAudit {
        pkesk_count,
        all_pkesk_anonymous,
        pkesk_versions,
        seipd_count,
        seipd_version,
        has_unauthenticated_sed,
        armor_has_version_or_comment,
    })
}
