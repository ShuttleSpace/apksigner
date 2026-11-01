# apksigner

Generate Android release signing keys, store them encrypted in a vault backend
(Bitwarden by default), and sign APKs — from the command line or via an
MCP server that an AI agent can drive.

The design goal is **key safety**: the private key / keystore password is never
printed, never placed on a process command line, and only briefly materialised in
a `0600` temp file (wiped immediately after use). The long-lived secret lives
only inside your vault.

## How it works

- **Key generation** uses the installed JDK `keytool` (the reference
  implementation `apksigner` consumes) to produce a PKCS#12 keystore. The
  password is generated in-process and handed to `keytool` through a `0600` temp
  file (`:file` syntax), never on the command line.
- **Storage** writes the keystore bytes + password to a `VaultBackend`. The
  default backend is Bitwarden (via the `bw` CLI), which encrypts
  everything client-side in your vault.
- **Signing** retrieves the keystore from the backend, writes it to a `0600` temp
  file, and calls `apksigner` with the password delivered through a
  child-process-only environment variable (`--ks-pass env:VAR`). The temp keystore
  is securely wiped afterwards. The password is never returned to a caller.
- **Backend interface** is an abstract `VaultBackend` trait, so other backends
  (e.g. 1Password, a KMS, an encrypted local file) can be added without touching
  the CLI or signing logic.

## Prerequisites

- JDK 17+ on `PATH` (provides `keytool` and `java`).
- Android `apksigner` on `PATH`, or set it explicitly (see Configuration).
- For the default backend: the Bitwarden CLI (`bw`) installed, logged
  in, and unlocked (`BW_SESSION` exported in the environment).

## Build

```sh
cargo build --release
# with the MCP server (stdio transport for agents):
cargo build --release --features mcp
```

## Configuration

`apksigner` reads `~/.config/apksigner/config.toml` (override with
`--config` or `APKSIGNER_CONFIG`). Example:

```toml
# Where to find the signing tools (resolved from PATH if omitted).
apksigner = "/path/to/android-sdk/build-tools/37.0.0/apksigner"

[backend]
# "bitwarden" (default) or "local" (unencrypted, dev only).
kind = "bitwarden"
# Store items under this Bitwarden folder (optional).
bitwarden_folder = "Android Signing Keys"
```

## Commands

```sh
# Generate a key, store it in the vault, print the vault id.
apksigner generate my-app --validity 3650

# List stored keys.
apksigner list

# Retrieve a keystore + password (prints password to stdout; use --out to export).
apksigner get my-app --out ./out

# Sign an APK (keystore is pulled from the vault; password never touches argv).
apksigner sign my-app ./app-release-unsigned.apk --output ./app-release.apk

# Verify an APK signature.
apksigner verify ./app-release.apk

# Delete a stored key (use --yes to skip the prompt).
apksigner delete my-app --yes
```

## Using from an AI agent (MCP)

Build with `--features mcp`, then expose the binary as an MCP server over stdio.
The agent spawns the process; the server exposes tools `list_keystores`,
`generate_keystore`, `sign_apk`, and `verify_apk`. The keystore password is
handled inside the process and is never sent back to the agent — only the signed
APK path and verification status are returned.

## Security notes

- `keytool` receives the password via a `0600` temp file; `apksigner` receives it
  via a child-only env var. Neither appears in process listings.
- Temp keystores / password files are written `0600` and overwritten with zeros
  before deletion.
- The `local` backend is **unencrypted** and intended only for development/testing.
  Prefer the Bitwarden backend for real keys.
