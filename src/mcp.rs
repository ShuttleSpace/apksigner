//! MCP server exposing the APK signing flow to an AI agent.
//!
//! Built with the `mcp` feature. The binary serves MCP over stdio transport, so
//! an agent (which spawns the process and speaks MCP over stdio) can list keys,
//! generate keys, sign an APK, and verify the result.
//!
//! Security posture: secrets (the keystore password) are never returned to the
//! agent through tool results. They are handled inside the process and handed to
//! `apksigner` via a child-process environment variable.

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};

use crate::backend::{self, store::LocalStore, VaultBackend, VaultRef};
use crate::config::{BackendKind, ResolvedConfig};
use crate::error::{AppError, Result as AppResult};
use crate::signer;

/// MCP server handle. Holds the resolved config, the vault backend (encrypted
/// backup), and the always-on local keystore repository so tools can sign
/// directly from local files and without the password ever entering arguments.
#[derive(Clone)]
pub struct ApkSignerServer {
    resolved: Arc<ResolvedConfig>,
    backend: Arc<dyn VaultBackend>,
    local_store: Arc<LocalStore>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl ApkSignerServer {
    pub fn new(
        resolved: ResolvedConfig,
        backend: Box<dyn VaultBackend>,
        local_store: LocalStore,
    ) -> Self {
        Self {
            resolved: Arc::new(resolved),
            backend: Arc::from(backend),
            local_store: Arc::new(local_store),
            tool_router: Self::tool_router(),
        }
    }
}

/// Parameters for the `sign_apk` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignApkParams {
    /// Absolute path to the unsigned APK to sign.
    pub apk_path: String,
    /// Signing key id: a bare alias (defaults to the "default" project) or
    /// "project/alias".
    pub key_id: String,
    /// Optional output path for the signed APK.
    #[serde(default)]
    pub output_path: Option<String>,
}

/// Parameters for the `generate_keystore` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeystoreParams {
    /// Project name (groups keys for management). Defaults to "default".
    #[serde(default)]
    pub name: Option<String>,
    /// Optional key alias to use.
    #[serde(default)]
    pub alias: Option<String>,
    /// Optional key validity in days.
    #[serde(default)]
    pub validity_days: Option<u32>,
}

/// Parameters for the `verify_apk` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyApkParams {
    /// Absolute path to the APK to verify.
    pub apk_path: String,
}

/// Convert an internal error into a JSON error string the agent can read.
fn err_json(err: &AppError) -> String {
    serde_json::to_string(&serde_json::json!({
        "error": true,
        "message": err.source.to_string(),
    }))
    .unwrap_or_else(|_| "{\"error\":true}".to_string())
}

/// Convert a successful JSON value into the tool string result.
fn ok_json(value: serde_json::Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

#[tool_router]
impl ApkSignerServer {
    #[tool(
        description = "Sign an Android APK using a keystore from the local keystore repository \
        (or the encrypted vault backup). Returns the signed APK path and verification status. \
        The keystore password never leaves the process."
    )]
    async fn sign_apk(&self, Parameters(params): Parameters<SignApkParams>) -> String {
        match self.do_sign(params).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(&e),
        }
    }

    #[tool(description = "List all Android signing keys stored in the encrypted vault.")]
    async fn list_keystores(&self) -> String {
        match self.do_list().await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(&e),
        }
    }

    #[tool(
        description = "Generate a new RSA-2048 Android signing key and store it encrypted in the \
        vault. Returns a reference (id) to the stored key."
    )]
    async fn generate_keystore(
        &self,
        Parameters(params): Parameters<GenerateKeystoreParams>,
    ) -> String {
        match self.do_generate(params).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(&e),
        }
    }

    #[tool(
        description = "Verify an Android APK signature. Returns verification status and which \
        signature schemes were verified."
    )]
    async fn verify_apk(&self, Parameters(params): Parameters<VerifyApkParams>) -> String {
        match self.do_verify(params).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(&e),
        }
    }
}

impl ApkSignerServer {
    async fn do_sign(&self, params: SignApkParams) -> AppResult<serde_json::Value> {
        let apk_path = std::path::PathBuf::from(&params.apk_path);
        let output_path = match params.output_path {
            Some(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
            _ => apk_path.with_extension("signed.apk"),
        };

        let (name, alias) = resolve_key_id(&params.key_id);
        let item = match self.local_store.load_key(&name, &alias) {
            Ok(i) => i,
            Err(_) => {
                // Fall back to the vault backup.
                let composite = backend::composite_key(&name, &alias);
                let id = self
                    .backend
                    .resolve_alias(&composite)?
                    .unwrap_or_else(|| composite.clone());
                self.backend.retrieve(&id)?
            }
        };
        crate::signer::sign_apk(
            &self.resolved.apksigner,
            &item.keystore,
            &item.password,
            &item.alias,
            &apk_path,
            &output_path,
        )?;
        let report = signer::verify_apk(&self.resolved.apksigner, &output_path)?;
        Ok(serde_json::json!({
            "signed": true,
            "apk_path": output_path.display().to_string(),
            "verified": report.verified,
            "v1_scheme": report.v1_scheme,
            "v2_scheme": report.v2_scheme,
            "v3_scheme": report.v3_scheme,
            "v4_scheme": report.v4_scheme,
        }))
    }

    async fn do_list(&self) -> AppResult<serde_json::Value> {
        let refs = self.local_store.list_keys()?;
        let arr = refs
            .iter()
            .map(|r: &VaultRef| -> serde_json::Value {
                let (name, alias) = split_key_id(&r.name);
                serde_json::json!({
                    "project": name,
                    "alias": alias,
                    "id": r.id,
                    "created_at": r.created_at,
                })
            })
            .collect::<Vec<serde_json::Value>>();
        Ok(serde_json::json!({ "count": arr.len(), "keystores": arr }))
    }

    async fn do_generate(&self, params: GenerateKeystoreParams) -> AppResult<serde_json::Value> {
        let name = params.name.unwrap_or_else(|| "default".to_string());
        let alias = match params.alias {
            Some(a) if !a.trim().is_empty() => a,
            _ => generate_alias(),
        };
        let validity = params.validity_days.unwrap_or(self.resolved.validity_days);
        let pw_len = self.resolved.password_length;

        let gen =
            crate::keygen::generate_keystore(&self.resolved.keytool, &alias, validity, pw_len)?;
        let item = backend::item_from_generated(
            name.clone(),
            alias.clone(),
            gen.keystore,
            gen.password,
            validity,
        );
        // Local copy first.
        let local_ref = self.local_store.store_key(&item)?;
        // Encrypted backup (skip when the backend is the local one).
        let mut backend_ref = None;
        if self.resolved.backend.kind != BackendKind::local {
            backend_ref = Some(self.backend.store(&item)?);
        }
        Ok(serde_json::json!({
            "generated": true,
            "project": name,
            "alias": alias,
            "local_id": local_ref.id,
            "backend_id": backend_ref.map(|r| r.id),
        }))
    }

    async fn do_verify(&self, params: VerifyApkParams) -> AppResult<serde_json::Value> {
        let report = signer::verify_apk(
            &self.resolved.apksigner,
            &std::path::PathBuf::from(params.apk_path),
        )?;
        Ok(serde_json::json!({
            "verified": report.verified,
            "v1_scheme": report.v1_scheme,
            "v2_scheme": report.v2_scheme,
            "v3_scheme": report.v3_scheme,
            "v4_scheme": report.v4_scheme,
        }))
    }
}

#[tool_handler]
impl ServerHandler for ApkSignerServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Android signing tool backed by an encrypted vault. Use list_keystores / \
                generate_keystore to manage keys and sign_apk to sign an APK.",
        )
    }
}

/// Serve the MCP server over stdio until the client disconnects.
pub async fn serve(resolved: &ResolvedConfig) -> AppResult<()> {
    let backend = backend::build_from_config(resolved)?;
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    let server = ApkSignerServer::new(resolved.clone(), backend, local);
    let transport = stdio();
    let service = server
        .serve(transport)
        .await
        .map_err(|e| AppError::external(format!("mcp server failed to start: {}", e)))?;
    service
        .waiting()
        .await
        .map_err(|e| AppError::external(format!("mcp server error: {}", e)))?;
    Ok(())
}

/// Split a key id into `(name, alias)`. A bare alias resolves to the "default"
/// project.
fn resolve_key_id(key_id: &str) -> (String, String) {
    match key_id.split_once('/') {
        Some((n, a)) => (n.to_string(), a.to_string()),
        None => ("default".to_string(), key_id.to_string()),
    }
}

/// Inverse of [`resolve_key_id`]: split a composite `"name/alias"` key.
fn split_key_id(composite: &str) -> (String, String) {
    match composite.split_once('/') {
        Some((n, a)) => (n.to_string(), a.to_string()),
        None => ("default".to_string(), composite.to_string()),
    }
}

/// Generate a random 6-character key alias.
fn generate_alias() -> String {
    (0..6)
        .map(|_| {
            let c = b"abcdefghijklmnopqrstuvwxyz0123456789";
            c[rand::random::<usize>() % c.len()] as char
        })
        .collect()
}
