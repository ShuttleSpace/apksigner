//! APK signing and verification via the Android `apksigner` tool.
//!
//! The keystore is materialised to a mode-0600 temp file and the password is
//! delivered to `apksigner` through a child-process-only environment variable
//! (`--ks-pass env:VAR`). Neither the keystore nor the password is ever placed
//! on the command line, and the temp keystore is securely deleted afterwards.

use std::path::Path;
use std::process::Command;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{AppError, Result};
use crate::util;

/// Environment variable name used to hand the password to `apksigner`.
const PW_ENV_VAR: &str = "APKSIGNER_KEY_PASSWORD";

/// Sign an APK in place or to a new output path.
///
/// * `apksigner` — path to the apksigner executable.
/// * `keystore`   — PKCS#12 keystore bytes.
/// * `password`   — keystore/key password.
/// * `alias`      — key alias inside the keystore.
/// * `input`      — unsigned APK path.
/// * `output`     — signed APK path (may equal `input` to overwrite).
pub fn sign_apk(
    apksigner: &Path,
    keystore: &[u8],
    password: &SecretString,
    alias: &str,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let tmp_dir = std::env::temp_dir();
    let unique = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let ks_path = tmp_dir.join(format!("apksigner-sign-{}.p12", unique));
    util::write_restricted(&ks_path, keystore)?;

    let status = Command::new(apksigner)
        .arg("sign")
        .arg("--ks")
        .arg(&ks_path)
        .arg("--ks-pass")
        .arg(format!("env:{}", PW_ENV_VAR))
        .arg("--key-pass")
        .arg(format!("env:{}", PW_ENV_VAR))
        .arg("--ks-key-alias")
        .arg(alias)
        .arg("--out")
        .arg(output)
        .arg(input)
        // Deliver the password only to the child process.
        .env(PW_ENV_VAR, password.expose_secret())
        .output()
        .map_err(|e| AppError::external(format!("failed to run apksigner: {}", e)));

    // Always try to wipe the keystore temp file first.
    let _ = util::secure_remove(&ks_path);

    let status = status?;
    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        return Err(AppError::external(format!(
            "apksigner failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// Result of verifying an APK's signature.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationReport {
    pub verified: bool,
    pub v1_scheme: bool,
    pub v2_scheme: bool,
    pub v3_scheme: bool,
    pub v4_scheme: bool,
    pub signer_names: Vec<String>,
    pub details: String,
}

/// Verify an APK signature. The output of `apksigner verify --verbose` is parsed
/// for scheme support and signer certificates.
pub fn verify_apk(apksigner: &Path, apk: &Path) -> Result<VerificationReport> {
    let status = Command::new(apksigner)
        .arg("verify")
        .arg("--verbose")
        .arg(apk)
        .output()
        .map_err(|e| AppError::external(format!("failed to run apksigner verify: {}", e)))?;

    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    let verified = status.status.success();
    let v1 = combined.contains("Verified using v1 scheme");
    let v2 = combined.contains("Verified using v2 scheme");
    let v3 = combined.contains("Verified using v3 scheme");
    let v4 = combined.contains("Verified using v4 scheme");

    let mut signer_names = Vec::new();
    for line in combined.lines() {
        if line.trim_start().starts_with("Signer #") {
            signer_names.push(line.trim().to_string());
        }
    }

    Ok(VerificationReport {
        verified,
        v1_scheme: v1,
        v2_scheme: v2,
        v3_scheme: v3,
        v4_scheme: v4,
        signer_names,
        details: combined.trim().to_string(),
    })
}
