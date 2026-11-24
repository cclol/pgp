use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct KeySummary {
    pub fingerprint: String,
    pub key_id: String,
    pub version: String,
    pub algorithm: String,
    pub has_secret: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub user_ids: Vec<String>,
    pub identity_confirmed: bool,
    pub created_at: u32,
}

pub struct StoredPublicKey {
    pub fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
    pub identity_confirmed: bool,
    pub key: SignedPublicKey,
}

pub struct StoredSecretKey {
    pub fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
    pub identity_confirmed: bool,
    pub key: SignedSecretKey,
}

#[derive(Default)]
pub struct SessionStore {
    pub public_keys: Vec<StoredPublicKey>,
    pub secret_keys: Vec<StoredSecretKey>,
}

impl SessionStore {
    pub fn wipe(&mut self) {
        self.secret_keys.clear();
        self.secret_keys.shrink_to_fit();
        self.public_keys.clear();
        self.public_keys.shrink_to_fit();
    }

    pub fn upsert_public(&mut self, key: SignedPublicKey, confirmed: bool) -> KeySummary {
        let fp = hex::encode_upper(key.primary_key.fingerprint().as_bytes());
        let key_id = hex::encode_upper(key.primary_key.legacy_key_id().as_ref());
        let user_ids: Vec<String> = key
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect();

        if let Some(existing) = self.public_keys.iter_mut().find(|k| k.fingerprint == fp) {
            existing.key = key;
            existing.user_ids = user_ids;
            if confirmed {
                existing.identity_confirmed = true;
            }
        } else {
            self.public_keys.push(StoredPublicKey {
                fingerprint: fp.clone(),
                key_id,
                user_ids,
                identity_confirmed: confirmed,
                key,
            });
        }

        self.list_keys()
            .into_iter()
            .find(|k| k.fingerprint == fp)
            .expect("inserted key must exist")
    }

    pub fn upsert_secret(&mut self, key: SignedSecretKey, confirmed: bool) -> KeySummary {
        let pub_key = key.to_public_key();
        let fp = hex::encode_upper(key.primary_key.fingerprint().as_bytes());
        let key_id = hex::encode_upper(key.primary_key.legacy_key_id().as_ref());
        let user_ids: Vec<String> = key
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect();

        if let Some(existing) = self.secret_keys.iter_mut().find(|k| k.fingerprint == fp) {
            existing.key = key;
            existing.user_ids = user_ids;
            if confirmed {
                existing.identity_confirmed = true;
            }
        } else {
            self.secret_keys.push(StoredSecretKey {
                fingerprint: fp.clone(),
                key_id,
                user_ids,
                identity_confirmed: confirmed,
                key,
            });
        }

        self.upsert_public(pub_key, confirmed)
    }

    pub fn confirm_identity(&mut self, fp: &str, confirmed: bool) -> Result<KeySummary, String> {
        let norm = fp.trim().to_uppercase();
        let mut found = false;
        if let Some(k) = self.public_keys.iter_mut().find(|k| k.fingerprint == norm) {
            k.identity_confirmed = confirmed;
            found = true;
        }
        if let Some(k) = self.secret_keys.iter_mut().find(|k| k.fingerprint == norm) {
            k.identity_confirmed = confirmed;
            found = true;
        }
        if !found {
            return Err("Schlüssel mit diesem Fingerprint nicht in der Sitzung gefunden.".into());
        }
        self.list_keys()
            .into_iter()
            .find(|k| k.fingerprint == norm)
            .ok_or_else(|| "Schlüssel nicht gefunden.".into())
    }

    pub fn remove_key(&mut self, fp: &str) -> bool {
        let norm = fp.trim().to_uppercase();
        let before = self.public_keys.len() + self.secret_keys.len();
        self.public_keys.retain(|k| k.fingerprint != norm);
        self.secret_keys.retain(|k| k.fingerprint != norm);
        (self.public_keys.len() + self.secret_keys.len()) < before
    }

    pub fn list_keys(&self) -> Vec<KeySummary> {
        self.public_keys
            .iter()
            .map(|pk| {
                let has_secret = self
                    .secret_keys
                    .iter()
                    .any(|sk| sk.fingerprint == pk.fingerprint);
                let can_encrypt = !pk.key.public_subkeys.is_empty()
                    || pk.key.primary_key.algorithm().can_encrypt();
                let can_sign = pk.key.primary_key.algorithm().can_sign()
                    || pk
                        .key
                        .public_subkeys
                        .iter()
                        .any(|s| s.key.algorithm().can_sign());
                KeySummary {
                    fingerprint: pk.fingerprint.clone(),
                    key_id: pk.key_id.clone(),
                    version: format!("{:?}", pk.key.primary_key.version()),
                    algorithm: format!("{:?}", pk.key.primary_key.algorithm()),
                    has_secret,
                    can_encrypt,
                    can_sign,
                    user_ids: pk.user_ids.clone(),
                    identity_confirmed: pk.identity_confirmed,
                    created_at: pk.key.primary_key.created_at().as_secs(),
                }
            })
            .collect()
    }
}
