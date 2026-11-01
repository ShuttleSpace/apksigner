//! Vault backend abstraction.
//!
//! The tool stores Android keystores and their passwords in an external secret
//! store ("vault"). This module defines the [`VaultBackend`] trait so that the
//! storage provider is pluggable: the current default is Bitwarden (via
//! the `bw` CLI), but a different backend (e.g. 1Password, a KMS, an encrypted
//! local file) can be added by implementing the same trait and registering it in
//! [`build_backend`].
//!
//! Security contract for all backends:
//! * Keystore bytes and passwords must be encrypted at rest by the backend.
//! * Secrets must never be written to logs, and only briefly materialised on disk
//!   (in temp files) when the signing process requires it.

pub mod bitwarden;
pub mod local;
pub mod store;

use secrecy::SecretString;

use crate::error::Result;

/// A signing key set to be stored in / retrieved from a vault.
///
/// `keystore` holds the binary keystore (PKCS#12) and `password` is the single
/// password used for both the keystore and the key entry (Android convention).
///
/// A key is identified by the combination of `name` (a project/grouping) and
/// `alias` (the key within that project); the two together form a unique key.
#[derive(Debug, Clone)]
pub struct VaultItem {
    /// Project name, used to group keys for management.
    pub name: String,
    /// Key alias within the project; combined with `name` for a unique key.
    pub alias: String,
    /// Binary keystore contents (PKCS#12 `.p12`/`.keystore`).
    pub keystore: Vec<u8>,
    /// The password protecting the keystore and key entry.
    pub password: SecretString,
    /// When the key was generated (RFC3339).
    pub created_at: String,
    /// Key validity in days (informational).
    pub validity_days: u32,
    /// Key algorithm, e.g. "RSA-2048".
    pub key_algorithm: String,
    /// Keystore format, e.g. "PKCS12".
    pub keystore_format: String,
}

/// A reference to a stored item, returned by list/store and used for retrieval.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultRef {
    /// Backend-specific identifier (e.g. the Bitwarden item UUID).
    pub id: String,
    /// Composite lookup key, `"name/alias"`.
    pub name: String,
    /// The alias the item was stored under.
    pub alias: String,
    /// Creation timestamp if known.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// A pluggable vault backend.
pub trait VaultBackend: Send + Sync {
    /// Stable backend name (e.g. "bitwarden").
    fn name(&self) -> &str;

    /// Persist a key set and return a reference that can later retrieve it.
    fn store(&self, item: &VaultItem) -> Result<VaultRef>;

    /// Retrieve a previously stored key set by its backend id.
    fn retrieve(&self, id: &str) -> Result<VaultItem>;

    /// List all stored Android signing keys.
    fn list(&self) -> Result<Vec<VaultRef>>;

    /// Delete a stored key set by its backend id.
    fn delete(&self, id: &str) -> Result<()>;

    /// Optional: resolve an alias to a backend id, or `None` if not present.
    fn resolve_alias(&self, alias: &str) -> Result<Option<String>> {
        let _ = alias;
        Ok(None)
    }
}

/// Build the configured backend.
pub fn build_backend(
    kind: crate::config::BackendKind,
    cfg: &crate::config::BackendConfig,
) -> Result<Box<dyn VaultBackend>> {
    match kind {
        crate::config::BackendKind::bitwarden => {
            Ok(Box::new(bitwarden::BitwardenBackend::new(cfg.clone())))
        }
        crate::config::BackendKind::local => Ok(Box::new(local::LocalBackend::new(cfg.clone())?)),
    }
}

/// Convenience: load + build the backend described by the resolved config.
pub fn build_from_config(cfg: &crate::config::ResolvedConfig) -> Result<Box<dyn VaultBackend>> {
    build_backend(cfg.backend.kind.clone(), &cfg.backend)
}

/// Combine a project `name` and key `alias` into a single composite lookup key.
pub fn composite_key(name: &str, alias: &str) -> String {
    format!("{}/{}", name, alias)
}

/// Build a vault item from generated key material, timestamping it now.
pub fn item_from_generated(
    name: String,
    alias: String,
    keystore: Vec<u8>,
    password: SecretString,
    validity_days: u32,
) -> VaultItem {
    VaultItem {
        name,
        alias,
        keystore,
        password,
        created_at: chrono::Utc::now().to_rfc3339(),
        validity_days,
        key_algorithm: "RSA-2048".to_string(),
        keystore_format: "PKCS12".to_string(),
    }
}
