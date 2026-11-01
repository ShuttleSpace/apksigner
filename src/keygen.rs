//! Android signing-key generation.
//!
//! Keystores are produced by the installed JDK's `keytool` (the reference
//! implementation that `apksigner` consumes), because it guarantees a keystore
//! format compatible with the Android signing tools. The generated password is
//! never placed on the command line: it is written to a mode-0600 temp file and
//! passed to `keytool` via its `:file` password syntax, then securely deleted.

use std::path::Path;
use std::process::Command;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{AppError, ErrorKind, Result};
use crate::secret::generate_password;
use crate::util;

/// Result of generating a keystore.
pub struct GeneratedKey {
    /// The keystore binary (PKCS#12).
    pub keystore: Vec<u8>,
    /// The password (used for both the keystore and the key entry).
    pub password: SecretString,
}

/// Generate an RSA-2048 signing keystore for `alias` using `keytool`.
///
/// * `keytool`  — path to the keytool executable.
/// * `alias`    — key alias inside the keystore.
/// * `validity` — validity in days.
/// * `password_len` — length of the randomly generated password.
///
/// The temporary keystore and password file are removed before this returns.
pub fn generate_keystore(
    keytool: &Path,
    alias: &str,
    validity: u32,
    password_len: usize,
) -> Result<GeneratedKey> {
    let password = generate_password(password_len);
    let tmp_dir = std::env::temp_dir();
    let unique = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let ks_path = tmp_dir.join(format!("apksigner-ks-{}.p12", unique));
    let pw_path = tmp_dir.join(format!("apksigner-pw-{}", unique));

    // Write password to a 0600 temp file. keytool reads it via the `-storepass:file`
    // / `-keypass:file` option-prefix syntax (NOT a `file:` value prefix).
    util::write_restricted(&pw_path, password.expose_secret().as_bytes())?;

    let dname = format!("CN={}, OU=Android, O=apksigner, L=NA, ST=NA, C=US", alias);

    let status = Command::new(keytool)
        .arg("-genkeypair")
        .arg("-alias")
        .arg(alias)
        .arg("-keyalg")
        .arg("RSA")
        .arg("-keysize")
        .arg("2048")
        .arg("-validity")
        .arg(validity.to_string())
        .arg("-keystore")
        .arg(&ks_path)
        .arg("-storetype")
        .arg("PKCS12")
        .arg("-storepass:file")
        .arg(&pw_path)
        .arg("-keypass:file")
        .arg(&pw_path)
        .arg("-dname")
        .arg(&dname)
        .arg("-noprompt")
        .output()
        .map_err(|e| AppError::external(format!("failed to run keytool: {}", e)))?;

    // Wipe the password file regardless of outcome.
    let _ = util::secure_remove(&pw_path);

    if !status.status.success() {
        let _ = util::secure_remove(&ks_path);
        let stderr = String::from_utf8_lossy(&status.stderr);
        return Err(AppError::external(format!(
            "keytool failed: {}",
            stderr.trim()
        )));
    }

    let keystore = std::fs::read(&ks_path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    // Wipe the keystore temp file.
    util::secure_remove(&ks_path)?;

    Ok(GeneratedKey { keystore, password })
}
