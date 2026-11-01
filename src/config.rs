//! Configuration for the tool.
//!
//! Settings are loaded from a TOML file located at
//! `~/.config/apksigner/config.toml` (overridable via `APKSIGNER_CONFIG`), with
//! individual fields overridable by environment variables. CLI flags take
//! precedence over both.

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{AppError, ErrorKind, Result};

/// The vault backend to use for storing/retrieving keystores.
///
/// The default backend is the Bitwarden CLI (`bw`), which encrypts the
/// keystore and password client-side in your vault.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum BackendKind {
    /// Bitwarden CLI (`bw`). The default.
    #[default]
    bitwarden,
    /// Plain local file store (development/testing only — not encrypted at rest).
    local,
}

/// Backend-specific configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BackendConfig {
    /// Which backend to use.
    #[serde(default)]
    pub kind: BackendKind,
    /// Bitwarden folder name to store items under (optional).
    #[serde(default)]
    pub bitwarden_folder: Option<String>,
    /// Path to the `bw` executable (optional; resolved from PATH).
    #[serde(default)]
    pub bitwarden_cli: Option<String>,
    /// Base directory for the local backend (optional).
    #[serde(default)]
    pub local_dir: Option<PathBuf>,
}

/// Tool configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// Path to the `keytool` executable.
    #[serde(default)]
    pub keytool: Option<String>,
    /// Path to the `apksigner` executable.
    #[serde(default)]
    pub apksigner: Option<String>,
    /// Default alias prefix for generated keys.
    #[serde(default)]
    pub alias_prefix: Option<String>,
    /// Key password length (minimum 6).
    #[serde(default)]
    pub password_length: Option<usize>,
    /// Key validity in days for generated keystores.
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Local keystore repository directory (always kept as a local working copy).
    #[serde(default)]
    pub keystore_dir: Option<PathBuf>,
    /// Backend configuration.
    #[serde(default)]
    pub backend: BackendConfig,
}

impl Config {
    /// Load configuration. CLI-provided values are applied on top by the caller
    /// (see [`crate::cli`] which merges overrides into a `ResolvedConfig`).
    pub fn load() -> Result<Config> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Config::default());
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| AppError::new(ErrorKind::Config, e))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| {
            AppError::config(format!("invalid config at {}: {}", path.display(), e))
        })?;
        Ok(cfg)
    }

    /// Locate the config file.
    pub fn config_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("APKSIGNER_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dir = dirs::config_dir()
            .ok_or_else(|| AppError::config("could not determine config directory"))?;
        Ok(dir.join("apksigner").join("config.toml"))
    }
}

/// Configuration after merging defaults and CLI overrides, ready to be used by
/// the commands.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub keytool: PathBuf,
    pub apksigner: PathBuf,
    pub alias_prefix: String,
    pub password_length: usize,
    pub validity_days: u32,
    /// Local keystore repository directory (always-on local copy).
    pub keystore_dir: PathBuf,
    pub backend: BackendConfig,
}

impl ResolvedConfig {
    /// Build a resolved config from a base [`Config`] plus optional overrides.
    pub fn new(base: &Config, overrides: &CliOverrides) -> Result<ResolvedConfig> {
        let keytool = crate::util::resolve_exe(
            "keytool",
            overrides.keytool.as_deref().or(base.keytool.as_deref()),
        )?;
        let apksigner = crate::util::resolve_exe(
            "apksigner",
            overrides.apksigner.as_deref().or(base.apksigner.as_deref()),
        )?;

        let mut backend = base.backend.clone();
        if let Some(ref kind) = overrides.backend {
            backend.kind = kind.clone();
        }
        if overrides.bitwarden_folder.is_some() {
            backend.bitwarden_folder = overrides.bitwarden_folder.clone();
        }
        if overrides.bitwarden_cli.is_some() {
            backend.bitwarden_cli = overrides.bitwarden_cli.clone();
        }
        if overrides.local_dir.is_some() {
            backend.local_dir = overrides.local_dir.clone();
        }

        let keystore_dir = base
            .keystore_dir
            .clone()
            .or_else(|| dirs::data_dir().map(|d| d.join("apksigner").join("keystores")))
            .ok_or_else(|| {
                AppError::config("could not determine data directory for the local keystore store")
            })?;

        Ok(ResolvedConfig {
            keytool,
            apksigner,
            alias_prefix: overrides
                .alias_prefix
                .clone()
                .or_else(|| base.alias_prefix.clone())
                .unwrap_or_else(|| "android".to_string()),
            password_length: overrides
                .password_length
                .or(base.password_length)
                .unwrap_or(crate::secret::DEFAULT_PASSWORD_LEN),
            validity_days: overrides
                .validity_days
                .or(base.validity_days)
                .unwrap_or(3650),
            keystore_dir,
            backend,
        })
    }
}

/// Overrides typically supplied via CLI flags.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub keytool: Option<String>,
    pub apksigner: Option<String>,
    pub alias_prefix: Option<String>,
    pub password_length: Option<usize>,
    pub validity_days: Option<u32>,
    pub backend: Option<BackendKind>,
    pub bitwarden_folder: Option<String>,
    pub bitwarden_cli: Option<String>,
    pub local_dir: Option<PathBuf>,
}
