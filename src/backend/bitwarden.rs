//! Bitwarden backend implemented on top of the official `bw` CLI.
//!
//! The keystore bytes and password are stored as a single encrypted secure-note
//! item in the user's vault. Bitwarden encrypts everything client-side
//! before it leaves the machine, so neither the keystore nor the password is ever
//! exposed to Bitwarden's servers in plaintext.
//!
//! The `bw` CLI must already be logged in and unlocked. The easiest way to run
//! this tool non-interactively (e.g. from an agent) is to export `BW_SESSION`
//! (from `bw unlock` or `bw login`) into the environment before invoking it.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{VaultBackend, VaultItem, VaultRef};
use crate::config::BackendConfig;
use crate::error::{AppError, Result};

/// Prefix used for item names so we can enumerate Android keys distinctly.
pub const ITEM_NAME_PREFIX: &str = "Android Signing Key: ";

/// Schema tag embedded in the stored note, allowing future format changes.
const SCHEMA: &str = "apksigner/1";

/// How `bw create item` expects its stdin payload to be encoded.
///
/// Modern Bitwarden CLI releases require the JSON to be base64-encoded
/// before being piped to `bw create item`. Some older releases instead accept
/// raw JSON directly, so we probe the installed CLI and fall back at runtime
/// instead of assuming a single format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CreateItemEncoding {
    /// Modern `bw`: stdin must be base64-encoded JSON.
    Base64,
    /// Older `bw`: stdin accepts raw JSON directly.
    Raw,
}

/// In-memory representation of what we persist inside the Bitwarden note.
#[derive(Serialize, Deserialize)]
struct StoredItem {
    schema: String,
    name: String,
    alias: String,
    created_at: String,
    validity_days: u32,
    key_algorithm: String,
    keystore_format: String,
    #[serde(with = "base64_string")]
    keystore_base64: Vec<u8>,
    password: String,
}

/// Inline base64 (de)serialization so the keystore is stored as text.
mod base64_string {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

pub struct BitwardenBackend {
    cli: String,
    folder: Option<String>,
    /// Cache for the folder id, resolved lazily.
    folder_id: Option<String>,
    /// Detected encoding for `bw create item` stdin payload (base64 vs raw JSON).
    encoding: Option<CreateItemEncoding>,
}

impl BitwardenBackend {
    pub fn new(cfg: BackendConfig) -> Self {
        Self {
            cli: cfg.bitwarden_cli.unwrap_or_else(|| "bw".to_string()),
            folder: cfg.bitwarden_folder,
            folder_id: None,
            encoding: None,
        }
    }

    /// Run a `bw` subcommand, optionally feeding `stdin_data` to its stdin.
    /// Returns stdout. Stderr is captured and surfaced on failure.
    fn run_bw(&self, args: &[&str], stdin_data: Option<&[u8]>) -> Result<String> {
        let mut cmd = Command::new(&self.cli);
        cmd.args(args);
        // Inherit BW_SESSION and the rest of the environment so `bw` can find a
        // valid session.
        cmd.envs(std::env::vars());
        if let Some(data) = stdin_data {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            let mut child = cmd.spawn().map_err(|e| {
                AppError::external(format!("failed to spawn '{}': {}", self.cli, e))
            })?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(data)
                    .map_err(|e| AppError::external(format!("writing to stdin: {}", e)))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| AppError::external(format!("waiting for '{}': {}", self.cli, e)))?;
            return Self::finish(&self.cli, args, out);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let out = cmd
            .output()
            .map_err(|e| AppError::external(format!("failed to run '{}': {}", self.cli, e)))?;
        Self::finish(&self.cli, args, out)
    }

    fn finish(cli: &str, args: &[&str], out: std::process::Output) -> Result<String> {
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).to_string());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        Err(AppError::vault(format!(
            "'{} {}' exited with {}: {}{}",
            cli,
            args.join(" "),
            out.status,
            stderr.trim(),
            if stdout.trim().is_empty() {
                String::new()
            } else {
                format!(" ({})", stdout.trim())
            }
        )))
    }

    /// Ensure the vault session is unlocked, returning a helpful error otherwise.
    fn ensure_unlocked(&self) -> Result<()> {
        let status = self.run_bw(&["status"], None)?;
        let parsed: serde_json::Value = serde_json::from_str(&status)
            .map_err(|e| AppError::vault(format!("could not parse 'bw status': {}", e)))?;
        match parsed.get("status").and_then(|v| v.as_str()) {
            Some("unlocked") => Ok(()),
            Some(s) => Err(AppError::vault(format!(
                "Bitwarden vault is '{}'. Unlock it first (e.g. `bw unlock` and export BW_SESSION) before using this tool.",
                s
            ))),
            None => Err(AppError::vault(
                "could not determine Bitwarden vault status",
            )),
        }
    }

    /// Detect how the installed `bw` CLI expects `bw create item`'s stdin
    /// payload to be encoded (base64 vs raw JSON). We parse `bw --version`; the
    /// 2024+ line requires base64-encoded input, while older releases accept raw
    /// JSON. If the version cannot be determined we optimistically assume base64
    /// and let `store` fall back at runtime if `bw` rejects it.
    fn detect_encoding(&mut self) -> CreateItemEncoding {
        if let Some(e) = self.encoding {
            return e;
        }
        let enc = self
            .run_bw(&["--version"], None)
            .ok()
            .and_then(|v| Self::parse_bw_major_year(&v))
            .map(|year| {
                if year >= 2024 {
                    CreateItemEncoding::Base64
                } else {
                    CreateItemEncoding::Raw
                }
            })
            .unwrap_or(CreateItemEncoding::Base64);
        self.encoding = Some(enc);
        enc
    }

    /// Parse the leading year component of a `bw --version` string
    /// (e.g. "2025.9.0" -> 2025).
    fn parse_bw_major_year(v: &str) -> Option<u32> {
        v.split(|c: char| c == '.' || c.is_whitespace())
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
    }

    /// Resolve the configured folder name to a folder id, if any.
    fn resolve_folder_id(&mut self) -> Result<Option<String>> {
        if self.folder_id.is_some() {
            return Ok(self.folder_id.clone());
        }
        let Some(folder_name) = &self.folder else {
            return Ok(None);
        };
        let out = self.run_bw(&["list", "folders"], None)?;
        let folders: Vec<serde_json::Value> = serde_json::from_str(&out)
            .map_err(|e| AppError::vault(format!("could not parse folders list: {}", e)))?;
        for f in folders {
            if f.get("name").and_then(|n| n.as_str()) == Some(folder_name.as_str()) {
                if let Some(id) = f.get("id").and_then(|i| i.as_str()) {
                    self.folder_id = Some(id.to_string());
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Err(AppError::vault(format!(
            "Bitwarden folder '{}' not found",
            folder_name
        )))
    }

    /// Find the backend id for an alias by searching item names.
    fn find_id_by_alias(&self, alias: &str) -> Result<Option<String>> {
        let expected_name = format!("{}{}", ITEM_NAME_PREFIX, alias);
        let out = self.run_bw(
            &["list", "items", "--search", ITEM_NAME_PREFIX.trim()],
            None,
        )?;
        let items: Vec<serde_json::Value> = serde_json::from_str(&out)
            .map_err(|e| AppError::vault(format!("could not parse items list: {}", e)))?;
        for it in items {
            if it.get("name").and_then(|n| n.as_str()) == Some(expected_name.as_str()) {
                if let Some(id) = it.get("id").and_then(|i| i.as_str()) {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }
}

impl VaultBackend for BitwardenBackend {
    fn name(&self) -> &str {
        "bitwarden"
    }

    fn store(&self, item: &VaultItem) -> Result<VaultRef> {
        let mut this = self.clone_for_mut()?;
        this.ensure_unlocked()?;

        let stored = StoredItem {
            schema: SCHEMA.to_string(),
            name: item.name.clone(),
            alias: item.alias.clone(),
            created_at: item.created_at.clone(),
            validity_days: item.validity_days,
            key_algorithm: item.key_algorithm.clone(),
            keystore_format: item.keystore_format.clone(),
            keystore_base64: item.keystore.clone(),
            password: item.password.expose_secret().to_string(),
        };
        let notes = serde_json::to_string(&stored)
            .map_err(|e| AppError::vault(format!("serialize item: {}", e)))?;
        let composite = super::composite_key(&item.name, &item.alias);
        let name = format!("{}{}", ITEM_NAME_PREFIX, composite);

        let mut template = serde_json::json!({
            "type": 2, // secure note
            "name": name,
            "notes": notes,
            "secureNote": { "type": 0 }, // SecureNoteType.Generic
            "fields": [],
            "login": null,
            "card": null,
            "identity": null,
            "sshKey": null,
            "favorite": false,
            "reprompt": 0,
        });
        if let Some(fid) = this.resolve_folder_id()? {
            template["folderId"] = serde_json::Value::String(fid);
        }

        let template_bytes = serde_json::to_vec(&template)
            .map_err(|e| AppError::vault(format!("serialize template: {}", e)))?;

        // The installed `bw` may expect base64-encoded JSON or raw JSON on stdin
        // depending on its version. Probe the preferred encoding and fall back to
        // the other if `bw` rejects the payload, so we never assume a single
        // format. The payload is never placed on the command line either way.
        let preferred = this.detect_encoding();
        let order = match preferred {
            CreateItemEncoding::Base64 => [CreateItemEncoding::Base64, CreateItemEncoding::Raw],
            CreateItemEncoding::Raw => [CreateItemEncoding::Raw, CreateItemEncoding::Base64],
        };

        let mut last_err = None;
        for enc in order {
            let payload: String = match enc {
                CreateItemEncoding::Base64 => {
                    base64::engine::general_purpose::STANDARD.encode(&template_bytes)
                }
                CreateItemEncoding::Raw => String::from_utf8_lossy(&template_bytes).into_owned(),
            };
            match this.run_bw(&["create", "item"], Some(payload.as_bytes())) {
                Ok(out) => {
                    this.encoding = Some(enc);
                    let created: serde_json::Value = serde_json::from_str(&out).map_err(|e| {
                        AppError::vault(format!("could not parse created item: {}", e))
                    })?;
                    let id = created
                        .get("id")
                        .and_then(|i| i.as_str())
                        .ok_or_else(|| AppError::vault("created Bitwarden item has no id"))?
                        .to_string();
                    return Ok(VaultRef {
                        id,
                        name: composite.clone(),
                        alias: composite.clone(),
                        created_at: Some(item.created_at.clone()),
                    });
                }
                Err(e) => {
                    // A parsing error means the encoding was wrong for this `bw`;
                    // try the other encoding rather than failing outright.
                    if e.to_string()
                        .contains("Error parsing the encoded request data")
                    {
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            AppError::vault("failed to create Bitwarden item: unsupported encoding")
        }))
    }

    fn retrieve(&self, id: &str) -> Result<VaultItem> {
        self.ensure_unlocked()?;
        let out = self.run_bw(&["get", "item", id], None)?;
        let item: serde_json::Value = serde_json::from_str(&out)
            .map_err(|e| AppError::vault(format!("could not parse item '{}': {}", id, e)))?;
        let notes = item
            .get("notes")
            .and_then(|n| n.as_str())
            .ok_or_else(|| AppError::vault(format!("item '{}' has no notes", id)))?;
        let stored: StoredItem = serde_json::from_str(notes)
            .map_err(|e| AppError::vault(format!("could not parse stored key: {}", e)))?;
        if stored.schema != SCHEMA {
            return Err(AppError::vault(format!(
                "unexpected schema '{}' for item '{}'",
                stored.schema, id
            )));
        }
        Ok(VaultItem {
            name: stored.name,
            alias: stored.alias,
            keystore: stored.keystore_base64,
            password: SecretString::from(stored.password),
            created_at: stored.created_at,
            validity_days: stored.validity_days,
            key_algorithm: stored.key_algorithm,
            keystore_format: stored.keystore_format,
        })
    }

    fn list(&self) -> Result<Vec<VaultRef>> {
        self.ensure_unlocked()?;
        let out = self.run_bw(
            &["list", "items", "--search", ITEM_NAME_PREFIX.trim()],
            None,
        )?;
        let items: Vec<serde_json::Value> = serde_json::from_str(&out)
            .map_err(|e| AppError::vault(format!("could not parse items list: {}", e)))?;
        let mut refs = Vec::new();
        for it in items {
            let name = match it.get("name").and_then(|n| n.as_str()) {
                Some(n) if n.starts_with(ITEM_NAME_PREFIX) => n.to_string(),
                _ => continue,
            };
            let alias = name[ITEM_NAME_PREFIX.len()..].to_string();
            let id = match it.get("id").and_then(|i| i.as_str()) {
                Some(i) => i.to_string(),
                None => continue,
            };
            let created_at = it
                .get("revisionDate")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            refs.push(VaultRef {
                id,
                name,
                alias,
                created_at,
            });
        }
        Ok(refs)
    }

    fn delete(&self, id: &str) -> Result<()> {
        self.ensure_unlocked()?;
        self.run_bw(&["delete", "item", id], None)?;
        Ok(())
    }

    fn resolve_alias(&self, alias: &str) -> Result<Option<String>> {
        self.find_id_by_alias(alias)
    }
}

impl BitwardenBackend {
    /// Helper to get a mutable clone of `self`; the backend is cheap to rebuild
    /// (it only holds configuration) and the trait method takes `&self`.
    fn clone_for_mut(&self) -> Result<BitwardenBackend> {
        Ok(BitwardenBackend {
            cli: self.cli.clone(),
            folder: self.folder.clone(),
            folder_id: self.folder_id.clone(),
            encoding: self.encoding,
        })
    }
}
