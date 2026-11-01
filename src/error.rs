//! Application-wide error types.
//!
//! All fallible operations in this crate surface through [`AppError`], which is a
//! thin wrapper around [`anyhow::Error`] augmented with a stable error category
//! so callers (including the MCP layer) can decide how to present failures.

use std::fmt;
use std::process::ExitCode;

/// High level error kind used for user-facing messages and MCP error mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A sub-process (keytool / apksigner / bw) failed or was missing.
    ExternalTool,
    /// The requested vault item was not found.
    NotFound,
    /// A configuration value was missing or invalid.
    Config,
    /// The vault backend rejected the operation (locked, auth, etc.).
    Vault,
    /// Any other internal / IO failure.
    Internal,
}

/// Top level error type.
#[derive(Debug, thiserror::Error)]
#[error("{kind}: {source}")]
pub struct AppError {
    pub kind: ErrorKind,
    #[source]
    pub source: anyhow::Error,
}

impl ErrorKind {
    /// Short, stable string used in messages and MCP error mapping.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::ExternalTool => "external-tool",
            ErrorKind::NotFound => "not-found",
            ErrorKind::Config => "config",
            ErrorKind::Vault => "vault",
            ErrorKind::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AppError {
    /// Build an error from any displayable value plus a kind.
    pub fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Self {
            kind,
            source: anyhow::Error::msg(source),
        }
    }

    /// Convenience constructor for [`ErrorKind::Internal`].
    pub fn internal<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(source: E) -> Self {
        Self::new(ErrorKind::Internal, source)
    }

    /// Convenience constructor for [`ErrorKind::Config`].
    pub fn config<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(source: E) -> Self {
        Self::new(ErrorKind::Config, source)
    }

    /// Convenience constructor for [`ErrorKind::NotFound`].
    pub fn not_found<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(source: E) -> Self {
        Self::new(ErrorKind::NotFound, source)
    }

    /// Convenience constructor for [`ErrorKind::Vault`].
    pub fn vault<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(source: E) -> Self {
        Self::new(ErrorKind::Vault, source)
    }

    /// Convenience constructor for [`ErrorKind::ExternalTool`].
    pub fn external<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(source: E) -> Self {
        Self::new(ErrorKind::ExternalTool, source)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(source: anyhow::Error) -> Self {
        Self::internal(source)
    }
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AppError>;

/// Convert a result into a process exit code while emitting a clean message.
///
/// Returns [`ExitCode::SUCCESS`] for `Ok` and prints the error to stderr for `Err`.
pub fn report_exit<T>(result: Result<T>) -> ExitCode {
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", err);
            // Walk the cause chain so the underlying reason is visible.
            let mut cause = err.source.source();
            while let Some(c) = cause {
                eprintln!("  caused by: {}", c);
                cause = c.source();
            }
            match err.kind {
                ErrorKind::NotFound => ExitCode::from(2),
                ErrorKind::Config => ExitCode::from(3),
                ErrorKind::Vault => ExitCode::from(4),
                ErrorKind::ExternalTool => ExitCode::from(5),
                ErrorKind::Internal => ExitCode::FAILURE,
            }
        }
    }
}
