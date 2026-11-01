//! Local keystore repository — the always-on local copy of signing keys.
//!
//! Every generated keystore is materialised here (mode 0600) so that signing can
//! proceed directly from local files without consulting the backend, and as a
//! working copy kept alongside the encrypted backend backup. The backend remains
//! the encrypted source of truth / backup; this store is the fast, local path
//! used by the CLI and the MCP server for signing.
//!
//! A key is identified by the combination of a project `name` and a key `alias`.
//! On disk each key is `<safe("name/alias")>.keystore` plus a sibling `.json`
//! metadata file, both written with mode 0600.

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{composite_key, VaultItem, VaultRef};
use crate::error::{AppError, ErrorKind, Result};
use crate::util;

/// Metadata persisted next to each keystore file.
#[derive(Serialize, Deserialize)]
struct LocalKeyMeta {
    name: String,
    alias: String,
    created_at: String,
    validity_days: u32,
    key_algorithm: String,
    keystore_format: String,
    password: String,
}

/// An always-on local repository of signing keys.
pub struct LocalStore {
    dir: PathBuf,
}

impl LocalStore {
    /// Open (creating if needed) the local repository under `dir`.
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        Ok(Self { dir })
    }

    /// The directory backing this store.
    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    fn safe_name(name: &str, alias: &str) -> String {
        sanitize(&composite_key(name, alias))
    }

    fn keystore_path(&self, name: &str, alias: &str) -> PathBuf {
        self.dir
            .join(format!("{}.keystore", Self::safe_name(name, alias)))
    }

    fn meta_path(&self, name: &str, alias: &str) -> PathBuf {
        self.dir
            .join(format!("{}.json", Self::safe_name(name, alias)))
    }

    /// Persist a key set locally (0600 files). Returns the composite reference.
    pub fn store_key(&self, item: &VaultItem) -> Result<VaultRef> {
        let ks_path = self.keystore_path(&item.name, &item.alias);
        let meta_path = self.meta_path(&item.name, &item.alias);
        util::write_restricted(&ks_path, &item.keystore)?;
        let meta = LocalKeyMeta {
            name: item.name.clone(),
            alias: item.alias.clone(),
            created_at: item.created_at.clone(),
            validity_days: item.validity_days,
            key_algorithm: item.key_algorithm.clone(),
            keystore_format: item.keystore_format.clone(),
            password: item.password.expose_secret().to_string(),
        };
        let meta_bytes =
            serde_json::to_vec_pretty(&meta).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        util::write_restricted(&meta_path, &meta_bytes)?;
        let composite = composite_key(&item.name, &item.alias);
        Ok(VaultRef {
            id: composite.clone(),
            name: composite.clone(),
            alias: composite,
            created_at: Some(item.created_at.clone()),
        })
    }

    /// Load a key set by project `name` and key `alias`.
    pub fn load_key(&self, name: &str, alias: &str) -> Result<VaultItem> {
        let meta_path = self.meta_path(name, alias);
        if !meta_path.exists() {
            return Err(AppError::not_found(format!(
                "no local keystore for '{}/{}' in {}",
                name,
                alias,
                self.dir.display()
            )));
        }
        let meta_bytes =
            std::fs::read(&meta_path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        let meta: LocalKeyMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        let keystore = std::fs::read(self.keystore_path(name, alias))
            .map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        Ok(VaultItem {
            name: meta.name,
            alias: meta.alias,
            keystore,
            password: SecretString::from(meta.password),
            created_at: meta.created_at,
            validity_days: meta.validity_days,
            key_algorithm: meta.key_algorithm,
            keystore_format: meta.keystore_format,
        })
    }

    /// List all locally stored keys.
    pub fn list_keys(&self) -> Result<Vec<VaultRef>> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        let mut refs = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let meta: LocalKeyMeta = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let composite = composite_key(&meta.name, &meta.alias);
            refs.push(VaultRef {
                id: composite.clone(),
                name: composite,
                alias: meta.alias,
                created_at: Some(meta.created_at),
            });
        }
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(refs)
    }

    /// Delete a key set by project `name` and key `alias`.
    pub fn delete_key(&self, name: &str, alias: &str) -> Result<()> {
        let ks_path = self.keystore_path(name, alias);
        let meta_path = self.meta_path(name, alias);
        for p in [&ks_path, &meta_path] {
            if p.exists() {
                util::secure_remove(p)?;
            }
        }
        Ok(())
    }
}

/// Restrict project/alias characters so they are safe as filenames.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
