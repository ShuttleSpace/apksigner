//! Local file backend — **development / testing only**.
//!
//! This backend stores keystores and passwords as plain files inside a directory.
//! It is NOT encrypted at rest and is therefore unsuitable for production secrets.
//! It exists to (a) demonstrate the [`super::VaultBackend`] interface and (b)
//! provide a usable fallback when Bitwarden is unavailable. In
//! production always use the Bitwarden backend (or another encrypted
//! backend).
//!
//! WARNING: files are written with mode 0600, but anyone who can read your user
//! account can read these secrets. Prefer the Bitwarden backend.

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{composite_key, VaultBackend, VaultItem, VaultRef};
use crate::config::BackendConfig;
use crate::error::{AppError, ErrorKind, Result};
use crate::util;

/// Metadata stored next to each keystore file.
#[derive(Serialize, Deserialize)]
struct LocalMeta {
    name: String,
    alias: String,
    created_at: String,
    validity_days: u32,
    key_algorithm: String,
    keystore_format: String,
    password: String,
}

pub struct LocalBackend {
    dir: PathBuf,
}

impl LocalBackend {
    pub fn new(cfg: BackendConfig) -> Result<Self> {
        let dir = match cfg.local_dir {
            Some(d) => d,
            None => {
                let base = dirs::data_dir().ok_or_else(|| {
                    AppError::config("could not determine data directory for local backend")
                })?;
                base.join("apksigner-keys")
            }
        };
        std::fs::create_dir_all(&dir).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        Ok(Self { dir })
    }

    fn keystore_path(&self, composite: &str) -> PathBuf {
        self.dir.join(format!("{}.keystore", sanitize(composite)))
    }

    fn meta_path(&self, composite: &str) -> PathBuf {
        self.dir.join(format!("{}.json", sanitize(composite)))
    }
}

/// Restrict alias characters so they are safe as filenames and lookups.
fn sanitize(alias: &str) -> String {
    alias
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl VaultBackend for LocalBackend {
    fn name(&self) -> &str {
        "local"
    }

    fn store(&self, item: &VaultItem) -> Result<VaultRef> {
        tracing::warn!(
            "using LOCAL (unencrypted) backend — secrets stored as plaintext files in {}",
            self.dir.display()
        );
        let composite = composite_key(&item.name, &item.alias);
        let ks_path = self.keystore_path(&composite);
        let meta_path = self.meta_path(&composite);

        util::write_restricted(&ks_path, &item.keystore)?;
        let meta = LocalMeta {
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

        Ok(VaultRef {
            id: composite.clone(),
            name: composite.clone(),
            alias: composite.clone(),
            created_at: Some(item.created_at.clone()),
        })
    }

    fn retrieve(&self, id: &str) -> Result<VaultItem> {
        let meta_path = self.meta_path(id);
        let ks_path = self.keystore_path(id);
        if !meta_path.exists() {
            return Err(AppError::not_found(format!("no local key for id '{}'", id)));
        }
        let meta_bytes =
            std::fs::read(&meta_path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        let meta: LocalMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| AppError::new(ErrorKind::Internal, e))?;
        let keystore =
            std::fs::read(&ks_path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
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

    fn list(&self) -> Result<Vec<VaultRef>> {
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
            let meta: LocalMeta = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };
            refs.push(VaultRef {
                id: composite_key(&meta.name, &meta.alias),
                name: composite_key(&meta.name, &meta.alias),
                alias: meta.alias,
                created_at: Some(meta.created_at),
            });
        }
        Ok(refs)
    }

    fn delete(&self, id: &str) -> Result<()> {
        let ks_path = self.keystore_path(id);
        let meta_path = self.meta_path(id);
        for p in [&ks_path, &meta_path] {
            if p.exists() {
                util::secure_remove(p)?;
            }
        }
        Ok(())
    }

    fn resolve_alias(&self, alias: &str) -> Result<Option<String>> {
        if self.meta_path(alias).exists() {
            Ok(Some(alias.to_string()))
        } else {
            Ok(None)
        }
    }
}
