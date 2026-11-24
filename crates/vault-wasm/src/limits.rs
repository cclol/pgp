use std::io::Read;
use pgp::packet::{PacketParser, PacketTrait};
use pgp::types::{S2kParams, StringToKey, Tag};
use zeroize::Zeroizing;

/// Hard security limits to bound memory and CPU consumption in browser Wasm.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
pub const MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
pub const MAX_DECOMPRESSION_RATIO: usize = 20;
pub const DECOMPRESSION_RATIO_FLOOR: usize = 64 * 1024; // 64 KiB floor before ratio check
pub const MAX_PACKETS: usize = 64;
pub const MAX_RECIPIENTS: usize = 32;
pub const MAX_ANON_DECRYPT_ATTEMPTS: usize = 32;
pub const MAX_KEYS_PER_IMPORT: usize = 16;

/// S2K resource limits (prevents browser OOM / tab freeze from malicious keys/SKESKs).
pub const MAX_ARGON2_MEM_EXP: u8 = 18; // 2^18 KiB = 256 MiB
pub const MAX_ARGON2_PASSES: u8 = 16;
pub const MAX_ARGON2_LANES: u8 = 16;
pub const MAX_S2K_ITER_CODED: u8 = 255; // ~65M bytes max

pub fn check_input_size(len: usize, label: &str) -> Result<(), String> {
    if len == 0 {
        return Err(format!("{label}: Eingabe ist leer."));
    }
    if len > MAX_INPUT_BYTES {
        return Err(format!(
            "{label}: Eingabe überschreitet Limit von {} MiB ({} Bytes).",
            MAX_INPUT_BYTES / (1024 * 1024),
            len
        ));
    }
    Ok(())
}

/// Counts top-level packets and rejects unauthenticated Tag 9 (SymEncryptedData) packets
/// or packet counts exceeding MAX_PACKETS.
pub fn inspect_raw_packets(bytes: &[u8]) -> Result<Vec<Tag>, String> {
    let mut tags = Vec::new();
    let parser = PacketParser::new(bytes);
    for pkt_res in parser {
        if tags.len() >= MAX_PACKETS {
            return Err(format!(
                "Paketanzahl überschreitet das Limit von {MAX_PACKETS} Paketen."
            ));
        }
        let pkt = pkt_res.map_err(|e| format!("Ungültiges OpenPGP-Paket: {e}"))?;
        let tag = pkt.tag();
        if tag == Tag::SymEncryptedData {
            return Err(
                "Abgelehnt: Unauthentifizierte verschlüsselte Nachricht (SED / Tag 9 ohne Integritätsschutz)."
                    .to_string(),
            );
        }
        tags.push(tag);
    }
    if tags.is_empty() {
        return Err("Keine gültigen OpenPGP-Pakete gefunden.".to_string());
    }
    Ok(tags)
}

pub fn check_s2k_string_to_key(s2k: &StringToKey) -> Result<(), String> {
    match s2k {
        StringToKey::Argon2 { t, p, m_enc, .. } => {
            if *m_enc > MAX_ARGON2_MEM_EXP {
                return Err(format!(
                    "S2K-Argon2-Speicherlimit überschritten (m_enc={m_enc} > {MAX_ARGON2_MEM_EXP}, max 256 MiB)."
                ));
            }
            if *t == 0 || *t > MAX_ARGON2_PASSES {
                return Err(format!(
                    "S2K-Argon2-Durchläufe außerhalb des Limits (t={t}, max {MAX_ARGON2_PASSES})."
                ));
            }
            if *p == 0 || *p > MAX_ARGON2_LANES {
                return Err(format!(
                    "S2K-Argon2-Parallelität außerhalb des Limits (p={p}, max {MAX_ARGON2_LANES})."
                ));
            }
            Ok(())
        }
        StringToKey::IteratedAndSalted { count, .. } => {
            if *count > MAX_S2K_ITER_CODED {
                return Err(format!(
                    "S2K-Iterationslimit überschritten (count={count})."
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn check_s2k_params(params: &S2kParams) -> Result<(), String> {
    match params {
        S2kParams::Aead { s2k, .. }
        | S2kParams::Cfb { s2k, .. }
        | S2kParams::MalleableCfb { s2k, .. } => check_s2k_string_to_key(s2k),
        S2kParams::Unprotected | S2kParams::LegacyCfb { .. } => Ok(()),
    }
}

/// Reads all bytes from `reader` into a `Zeroizing<Vec<u8>>` while enforcing
/// maximum output size and (when compressed) decompression ratio limits.
/// Returns Err (and automatically zeroizes partial data) if any limit or integrity check fails.
pub fn read_all_with_limits<R: Read>(
    mut reader: R,
    input_len: usize,
    is_compressed: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let ratio_cap = if is_compressed {
        let scaled = input_len.saturating_mul(MAX_DECOMPRESSION_RATIO);
        scaled.max(DECOMPRESSION_RATIO_FLOOR).min(MAX_DECOMPRESSED_BYTES)
    } else {
        MAX_DECOMPRESSED_BYTES
    };
    let hard_cap = ratio_cap.min(MAX_DECOMPRESSED_BYTES);

    let mut out = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = reader
            .read(&mut chunk[..])
            .map_err(|e| format!("Fehler beim Lesen/Prüfen der Nachricht (Integrität oder Format): {e}"))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > hard_cap {
            return Err(format!(
                "Ausgabe-/Dekompressionslimit überschritten (max {} Bytes).",
                hard_cap
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}
