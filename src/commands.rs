//! Command implementations and dispatch.

use std::io::Write;

use crate::backend::{self, store::LocalStore, VaultBackend, VaultItem};
use crate::cli::{Cli, Commands};
use crate::config::{BackendKind, CliOverrides, Config, ResolvedConfig};
use crate::error::{AppError, Result};
use crate::keygen;
use crate::signer;
use crate::util;
use secrecy::ExposeSecret;

/// Build overrides from the global CLI flags.
fn overrides(cli: &Cli) -> CliOverrides {
    CliOverrides {
        keytool: cli.keytool.clone(),
        apksigner: cli.apksigner.clone(),
        backend: cli.backend.map(|b| b.into()),
        bitwarden_folder: cli.bitwarden_folder.clone(),
        bitwarden_cli: cli.bitwarden_cli.clone(),
        local_dir: cli.local_dir.clone(),
        ..Default::default()
    }
}

/// Load config: explicit `--config`, else `APKSIGNER_CONFIG`, else default path.
fn load_config(cli: &Cli) -> Result<Config> {
    if let Some(path) = &cli.config {
        let text = std::fs::read_to_string(path)
            .map_err(|e| AppError::config(format!("reading config {}: {}", path.display(), e)))?;
        return toml::from_str(&text)
            .map_err(|e| AppError::config(format!("parsing config: {}", e)));
    }
    Config::load()
}

/// Resolve a key target (alias, or "name/alias") plus an optional `--name` into a
/// composite `"name/alias"` lookup key.
fn resolve_composite(target: &str, name: Option<&str>) -> String {
    if target.contains('/') {
        target.to_string()
    } else if let Some(n) = name {
        backend::composite_key(n, target)
    } else {
        backend::composite_key("default", target)
    }
}

/// Split a composite `"name/alias"` key into its `(name, alias)` parts.
fn split_composite(composite: &str) -> (String, String) {
    match composite.split_once('/') {
        Some((n, a)) => (n.to_string(), a.to_string()),
        None => ("default".to_string(), composite.to_string()),
    }
}

/// Resolve a key target into a `(name, alias)` pair for the local store.
fn resolve_local(target: &str, name: Option<&str>) -> (String, String) {
    split_composite(&resolve_composite(target, name))
}

/// Top-level entry point.
pub fn run(cli: Cli) -> Result<()> {
    let base = load_config(&cli)?;
    let resolved = ResolvedConfig::new(&base, &overrides(&cli))?;
    let backend = backend::build_from_config(&resolved)?;

    match &cli.command {
        Commands::Generate {
            name,
            alias,
            validity,
            password_length,
            export,
        } => cmd_generate(
            &resolved,
            backend.as_ref(),
            name,
            alias,
            *validity,
            *password_length,
            export,
        ),
        Commands::List { name } => cmd_list(&resolved, name.as_deref()),
        Commands::Get { target, name, out } => cmd_get(
            &resolved,
            backend.as_ref(),
            target,
            name.as_deref(),
            out.as_ref(),
        ),
        Commands::Sign {
            target,
            name,
            apk,
            output,
        } => cmd_sign(
            &resolved,
            backend.as_ref(),
            target,
            name.as_deref(),
            apk,
            output.as_ref(),
        ),
        Commands::Verify { apk } => cmd_verify(&resolved, apk),
        Commands::Delete { target, name, yes } => {
            cmd_delete(&resolved, backend.as_ref(), target, name.as_deref(), *yes)
        }
        #[cfg(feature = "mcp")]
        Commands::Serve => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| AppError::external(format!("failed to build tokio runtime: {}", e)))?;
            rt.block_on(crate::mcp::serve(&resolved))
        }
    }
}

fn effective_validity(resolved: &ResolvedConfig, override_v: Option<u32>) -> u32 {
    override_v.unwrap_or(resolved.validity_days)
}

fn effective_pw_len(resolved: &ResolvedConfig, override_v: Option<usize>) -> usize {
    override_v.unwrap_or(resolved.password_length)
}

/// Generate a random key alias (project-unique when combined with the project name).
fn generate_alias() -> String {
    (0..6)
        .map(|_| {
            let c = b"abcdefghijklmnopqrstuvwxyz0123456789";
            c[rand::random::<usize>() % c.len()] as char
        })
        .collect()
}

fn cmd_generate(
    resolved: &ResolvedConfig,
    backend: &dyn VaultBackend,
    name_opt: &Option<String>,
    alias_opt: &Option<String>,
    validity: Option<u32>,
    password_length: Option<usize>,
    export: &Option<std::path::PathBuf>,
) -> Result<()> {
    let name = name_opt.clone().unwrap_or_else(|| "default".to_string());
    let alias = alias_opt.clone().unwrap_or_else(generate_alias);
    let validity = effective_validity(resolved, validity);
    let pw_len = effective_pw_len(resolved, password_length);

    eprintln!(
        "generating RSA-2048 signing key '{}/{}' (valid {} days)...",
        name, alias, validity
    );
    let gen = keygen::generate_keystore(&resolved.keytool, &alias, validity, pw_len)?;

    let item = backend::item_from_generated(
        name.clone(),
        alias.clone(),
        gen.keystore,
        gen.password,
        validity,
    );

    // 1) Always keep a local copy (0600 files) for fast, local signing.
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    let local_ref = local.store_key(&item)?;

    // 2) Back up encrypted in the vault, unless the backend is the local one.
    let mut backend_ref = None;
    if resolved.backend.kind != BackendKind::local {
        backend_ref = Some(backend.store(&item)?);
    }

    println!("stored signing key locally at {}", local.dir().display());
    println!("  project : {}", name);
    println!("  alias   : {}", alias);
    println!("  local id: {}", local_ref.id);
    if let Some(b) = &backend_ref {
        println!("  backend ({}): {}", backend.name(), b.id);
    } else {
        println!("  backend : (skipped; backend is local)");
    }

    if let Some(dir) = export {
        export_keystore(dir, &item)?;
    }
    Ok(())
}

fn export_keystore(dir: &std::path::Path, item: &VaultItem) -> Result<()> {
    tracing::warn!(
        "exporting keystore + password to {} (these files are sensitive)",
        dir.display()
    );
    let ks_path = dir.join(format!("{}.keystore", sanitize(&item.alias)));
    let pw_path = dir.join(format!("{}.password.txt", sanitize(&item.alias)));
    util::write_restricted(&ks_path, &item.keystore)?;
    util::write_restricted(pw_path, item.password.expose_secret().as_bytes())?;
    println!("exported keystore to {}", ks_path.display());
    Ok(())
}

fn cmd_list(resolved: &ResolvedConfig, name_filter: Option<&str>) -> Result<()> {
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    let mut refs = local.list_keys()?;
    if let Some(n) = name_filter {
        let prefix = format!("{}/", n);
        refs.retain(|r| r.name == n || r.name.starts_with(&prefix));
    }
    if refs.is_empty() {
        println!("no signing keys found in the local keystore repository");
        return Ok(());
    }
    println!(
        "signing keys in local repository '{}':",
        local.dir().display()
    );
    for r in &refs {
        let (name, alias) = split_composite(&r.name);
        let created = r.created_at.as_deref().unwrap_or("-");
        println!(
            "  project={}  alias={}  id={}  created={}",
            name, alias, r.id, created
        );
    }
    Ok(())
}

fn cmd_get(
    resolved: &ResolvedConfig,
    backend: &dyn VaultBackend,
    target: &str,
    name: Option<&str>,
    out: Option<&std::path::PathBuf>,
) -> Result<()> {
    let (proj, alias) = resolve_local(target, name);
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    let item = match local.load_key(&proj, &alias) {
        Ok(i) => i,
        Err(_) => {
            // Fall back to the vault backup.
            let composite = backend::composite_key(&proj, &alias);
            let id = backend
                .resolve_alias(&composite)?
                .unwrap_or_else(|| composite.clone());
            backend.retrieve(&id)?
        }
    };
    println!("project     : {}", item.name);
    println!("alias       : {}", item.alias);
    println!("created     : {}", item.created_at);
    println!("key algorithm: {}", item.key_algorithm);
    println!("keystore fmt : {}", item.keystore_format);
    println!("password    : {}", item.password.expose_secret());
    if let Some(dir) = out {
        export_keystore(dir, &item)?;
    }
    Ok(())
}

fn cmd_sign(
    resolved: &ResolvedConfig,
    backend: &dyn VaultBackend,
    target: &str,
    name: Option<&str>,
    apk: &std::path::Path,
    output: Option<&std::path::PathBuf>,
) -> Result<()> {
    if !apk.exists() {
        return Err(AppError::config(format!(
            "APK not found: {}",
            apk.display()
        )));
    }
    let (proj, alias) = resolve_local(target, name);
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    let item = match local.load_key(&proj, &alias) {
        Ok(i) => i,
        Err(_) => {
            // Fall back to the vault backup.
            let composite = backend::composite_key(&proj, &alias);
            let id = backend
                .resolve_alias(&composite)?
                .unwrap_or_else(|| composite.clone());
            backend.retrieve(&id)?
        }
    };

    let output = match output {
        Some(o) => o.clone(),
        None => {
            let mut p = apk.to_path_buf();
            p.set_extension("signed.apk");
            p
        }
    };

    eprintln!(
        "signing {} with '{}/{}' (key alias '{}')...",
        apk.display(),
        proj,
        alias,
        item.alias
    );
    signer::sign_apk(
        &resolved.apksigner,
        &item.keystore,
        &item.password,
        &item.alias,
        apk,
        &output,
    )?;

    println!("signed APK written to {}", output.display());

    // Verify the result so the caller gets immediate confidence.
    let report = signer::verify_apk(&resolved.apksigner, &output)?;
    if report.verified {
        println!(
            "verified: v1={} v2={} v3={} v4={}",
            report.v1_scheme, report.v2_scheme, report.v3_scheme, report.v4_scheme
        );
    } else {
        return Err(AppError::external("signed APK failed verification"));
    }
    Ok(())
}

fn cmd_verify(resolved: &ResolvedConfig, apk: &std::path::Path) -> Result<()> {
    let report = signer::verify_apk(&resolved.apksigner, apk)?;
    if report.verified {
        println!("APK verified successfully.");
        println!(
            "schemes: v1={} v2={} v3={} v4={}",
            report.v1_scheme, report.v2_scheme, report.v3_scheme, report.v4_scheme
        );
        for s in &report.signer_names {
            println!("  {}", s);
        }
    } else {
        eprintln!("APK verification FAILED:");
        eprintln!("{}", report.details);
        return Err(AppError::external("APK verification failed"));
    }
    Ok(())
}

fn cmd_delete(
    resolved: &ResolvedConfig,
    backend: &dyn VaultBackend,
    target: &str,
    name: Option<&str>,
    yes: bool,
) -> Result<()> {
    let (proj, alias) = resolve_local(target, name);
    if !yes {
        print!(
            "Delete keystore '{}/{}' from the local repository and vault? [y/N] ",
            proj, alias
        );
        std::io::stdout().flush().ok();
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).ok();
        if !matches!(buf.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("aborted");
            return Ok(());
        }
    }
    // Delete the local copy.
    let local = LocalStore::new(resolved.keystore_dir.clone())?;
    local.delete_key(&proj, &alias)?;
    println!("deleted '{}/{}' from the local repository", proj, alias);
    // Delete the vault backup (when the backend is not the local one).
    if resolved.backend.kind != BackendKind::local {
        let composite = backend::composite_key(&proj, &alias);
        if let Some(id) = backend.resolve_alias(&composite)? {
            backend.delete(&id)?;
            println!("deleted backup from backend '{}'", backend.name());
        }
    }
    Ok(())
}

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
