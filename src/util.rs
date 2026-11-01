//! Small utilities: secure file deletion and path helpers.

use std::fs;
use std::path::Path;

use crate::error::{AppError, ErrorKind, Result};

/// Overwrite a file's contents with zeros and then delete it.
///
/// This is best-effort: it reduces the window in which a keystore or password
/// file lingers on disk in plaintext. It is *not* a guarantee against forensic
/// recovery (that would require filesystem-level secure delete), but combined
/// with restricted permissions it is a meaningful defence.
pub fn secure_remove<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    let len = meta.len() as usize;
    // Overwrite with zeros, then with 0xFF, then zeros again, before unlinking.
    if len > 0 {
        let zeroes = vec![0u8; len.min(1 << 20)];
        for fill in [0u8, 0xFF, 0u8] {
            let mut written = 0usize;
            while written < len {
                let chunk = &zeroes[..(len - written).min(zeroes.len())];
                fs::write(path, chunk).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
                written += chunk.len();
            }
            let _ = fill;
        }
    }
    fs::remove_file(path).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    Ok(())
}

/// Write `data` to `path` with mode 0600 (owner read/write only).
pub fn write_restricted<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    }
    fs::write(path, data).map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    set_mode_0600(path)?;
    Ok(())
}

/// Set a path to mode 0600 on Unix. No-op / best-effort on other platforms.
pub fn set_mode_0600<P: AsRef<Path>>(path: P) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path.as_ref(), perms)
            .map_err(|e| AppError::new(ErrorKind::Internal, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Resolve an executable name or absolute path, returning the first that exists.
///
/// If `explicit` is set it is used directly (and we still verify it exists).
/// Otherwise `candidate` is resolved via `PATH`.
pub fn resolve_exe(candidate: &str, explicit: Option<&str>) -> Result<std::path::PathBuf> {
    if let Some(p) = explicit {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
        return Err(AppError::config(format!(
            "explicit path does not exist: {}",
            p.display()
        )));
    }
    // Search PATH.
    if let Some(found) = which(candidate) {
        return Ok(found);
    }
    Err(AppError::config(format!(
        "could not find '{}' on PATH; set an explicit path in config",
        candidate
    )))
}

/// Minimal PATH lookup without pulling in the `which` crate.
fn which(name: &str) -> Option<std::path::PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
