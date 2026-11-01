//! Command-line interface definitions (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::BackendKind;

/// Backend selection for the CLI (`--backend`). Maps to [`BackendKind`].
#[derive(Debug, Clone, Copy, ValueEnum)]
#[allow(non_camel_case_types)]
pub enum BackendArg {
    /// Bitwarden CLI backend.
    bitwarden,
    /// Local (unencrypted) file backend.
    local,
}

impl From<BackendArg> for BackendKind {
    fn from(b: BackendArg) -> Self {
        match b {
            BackendArg::bitwarden => BackendKind::bitwarden,
            BackendArg::local => BackendKind::local,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "apksigner",
    version,
    about = "Generate Android signing keys, store them encrypted in a vault, and sign APKs safely.",
    long_about = None
)]
pub struct Cli {
    /// Path to the `keytool` executable (defaults to resolving from PATH).
    #[arg(long, global = true)]
    pub keytool: Option<String>,

    /// Path to the `apksigner` executable (defaults to resolving from PATH).
    #[arg(long, global = true)]
    pub apksigner: Option<String>,

    /// Vault backend to use. Default from config (Bitwarden).
    #[arg(long, global = true, value_enum)]
    pub backend: Option<BackendArg>,

    /// Path to the config file (overrides APKSIGNER_CONFIG env var).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Bitwarden folder to store items under.
    #[arg(long = "bw-folder", global = true)]
    pub bitwarden_folder: Option<String>,

    /// Path to the `bw` executable.
    #[arg(long = "bw-cli", global = true)]
    pub bitwarden_cli: Option<String>,

    /// Base directory for the local backend.
    #[arg(long = "local-dir", global = true)]
    pub local_dir: Option<PathBuf>,

    /// Increase verbosity (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a new RSA-2048 signing keystore. It is written to the local
    /// keystore repository (0600 files) and, unless the backend is `local`, also
    /// backed up encrypted in the configured vault.
    Generate {
        /// Project name used to group keys for management. Defaults to "default".
        #[arg(long)]
        name: Option<String>,

        /// Key alias within the project. A random one is generated if omitted.
        #[arg(long)]
        alias: Option<String>,

        /// Key validity in days (Android default: 3650).
        #[arg(long)]
        validity: Option<u32>,

        /// Password length (minimum 6).
        #[arg(long)]
        password_length: Option<usize>,

        /// Also export the keystore + password to this directory (0600 files).
        /// Optional convenience; secrets are still stored in the vault.
        #[arg(long)]
        export: Option<PathBuf>,
    },

    /// List signing keys stored in the local keystore repository.
    List {
        /// Optional project name filter.
        #[arg(long)]
        name: Option<String>,
    },

    /// Retrieve a keystore from the local repository (or vault). Prints the id
    /// and (optionally) exports the keystore + password to a directory.
    Get {
        /// Key id: an alias, or "name/alias".
        target: String,

        /// Optional project name when `target` is just an alias.
        #[arg(long)]
        name: Option<String>,

        /// Export the keystore + password to this directory (0600 files).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Sign an APK using a keystore from the local repository (or vault). The
    /// keystore is only briefly materialised in a 0600 temp file and the password
    /// is passed via an env var.
    Sign {
        /// Key id: an alias, or "name/alias".
        target: String,

        /// Optional project name when `target` is just an alias.
        #[arg(long)]
        name: Option<String>,

        /// Unsigned APK to sign.
        apk: PathBuf,

        /// Output signed APK. Defaults to `<apk>.signed`.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Verify an APK's signature.
    Verify {
        /// APK to verify.
        apk: PathBuf,
    },

    /// Delete a keystore from the local repository and the vault. Use with care —
    /// this cannot be undone.
    Delete {
        /// Key id: an alias, or "name/alias".
        target: String,

        /// Optional project name when `target` is just an alias.
        #[arg(long)]
        name: Option<String>,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },

    /// Start an MCP server over stdio so an AI agent can request APK signing.
    #[cfg(feature = "mcp")]
    Serve,
}
