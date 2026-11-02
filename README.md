# apksigner

[![release](https://img.shields.io/github/actions/workflow/status/ShuttleSpace/apksigner/release.yml?label=release&logo=github)](https://github.com/ShuttleSpace/apksigner/actions)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Generate Android release signing keys, keep a local copy, back them up
encrypted in a vault (Bitwarden by default), and sign APKs — from the
command line or through an MCP server that an AI agent can drive.

The design goal is **key safety**: the private key and keystore password are
never printed to logs, never placed on a process command line, and only briefly
materialised in a `0600` temp file that is wiped immediately after use. The
long-lived secret lives only inside your vault.

---

## Features

- **Dual storage** — every generated keystore is written to a local keystore
  repository (`0600` files) *and* backed up encrypted in the vault backend
  (`Bitwarden`). Signing runs straight from the local copy, so it works
  even when the vault is locked or offline.
- **Per-project key management** — a key is identified by a composite
  `name/alias` id. `name` groups keys by project/app; `alias` is the key within
  that project. Different projects may reuse the same alias.
- **Safe signing** — the keystore is materialised in a `0600` temp file and the
  password is handed to Android `apksigner` through a child-only environment
  variable (`--ks-pass env:VAR`), never as an argument.
- **MCP server** — with `--features mcp`, the binary serves MCP over stdio and
  exposes `generate_keystore`, `list_keystores`, `sign_apk`, and `verify_apk`
  tools. The password is handled inside the process and never returned to the
  agent.
- **Pluggable backends** — the `VaultBackend` trait abstracts storage, so more
  backends (1Password, a KMS, an encrypted file) can be added without touching
  the CLI or signing logic.

---

## How it works

1. **Generation** uses the installed JDK `keytool` (the reference
   implementation that Android's `apksigner` consumes) to produce a PKCS#12
   keystore. The password is generated in-process and passed to `keytool`
   through a `0600` temp file (`:file` syntax) — never on the command line.
2. **Storage** writes the keystore + password to the local repository and then
   to the configured `VaultBackend`. The default backend is Bitwarden
   (via the `bw` CLI), which encrypts everything client-side in your vault.
3. **Signing** loads the keystore from the local repository (falling back to the
   vault), writes it to a `0600` temp file, and calls `apksigner` with the
   password delivered through a child-process-only env var
   (`--ks-pass env:VAR`). The temp file is overwritten with zeros and deleted
   afterwards.

### Layout on disk

| What | Location |
| --- | --- |
| Config file | `dirs::config_dir()/apksigner/config.toml` (`~/.config/...` on Linux, `~/Library/Application Support/...` on macOS, `%APPDATA%\...` on Windows) |
| Local keystore repo | `dirs::data_dir()/apksigner/keystores` (override with `keystore_dir`) — `<name>_<alias>.keystore` + `.json` metadata, both `0600` |
| Vault backup | One secure-note item per key in the Bitwarden vault |

---

## Prerequisites

- **JDK 17+** on `PATH` (provides `keytool` and `java`).
- **Android `apksigner`** on `PATH`, or configured explicitly (see below). It
  ships with the Android SDK build-tools.
- For the default backend: the **Bitwarden CLI (`bw`)** installed,
  logged in, and unlocked — export a session token:

  ```sh
  export BW_SESSION="$(bw unlock --raw)"
  ```

  > Tip: self-hosted servers work too — `bw config server https://your.host/path`
  > before logging in.

---

## Install

### Prebuilt binaries

Download the archive for your platform from the
[Releases](https://github.com/ShuttleSpace/apksigner/releases) page:

| Platform | Archive |
| --- | --- |
| Linux x86_64 | `apksigner-x86_64-unknown-linux-gnu.tar.gz` |
| macOS arm64 | `apksigner-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `apksigner-x86_64-pc-windows-msvc.zip` |

Extract the `apksigner` binary (or `apksigner.exe`) and put it on your `PATH`.

### From source

```sh
git clone https://github.com/ShuttleSpace/apksigner
cd apksigner

# CLI only
cargo build --release

# with the MCP server (stdio transport for agents)
cargo build --release --features mcp
```

The binary is written to `target/release/apksigner`.

---

## Configuration

`apksigner` reads its config from `dirs::config_dir()/apksigner/config.toml`,
overridable with `--config <path>` or the `APKSIGNER_CONFIG` env var. All fields
are optional:

```toml
# Paths to the signing tools (resolved from PATH when omitted).
keytool   = "keytool"
apksigner = "/path/to/android-sdk/build-tools/37.0.0/apksigner"

# Defaults for generated keys.
password_length = 32     # minimum 6
validity_days   = 3650

# Local keystore repository (default: dirs::data_dir()/apksigner/keystores).
keystore_dir = "/path/to/keystores"

[backend]
# "bitwarden" (default) or "local" (unencrypted — development only).
kind = "bitwarden"
# Store vault items under this Bitwarden folder (optional).
bitwarden_folder = "Android Signing Keys"
# Path to the `bw` executable (optional; resolved from PATH).
# bitwarden_cli = "bw"
# Base directory for the `local` backend (optional).
# local_dir = "~/.local/share/apksigner-keys"
```

Global CLI flags override the config file: `--keytool`, `--apksigner`,
`--backend <bitwarden|local>`, `--bw-folder`, `--bw-cli`, `--local-dir`,
`--config`, and `-v/-vv` for verbosity.

---

## Usage

Keys are addressed by `name/alias`. A bare alias means the `default` project.

```sh
# Generate a key in project "acme" under alias "release".
# Writes a local copy and (unless backend=local) a vault backup.
apksigner generate --name acme --alias release --validity 3650

# List keys in the local repository (optionally filter by project).
apksigner list
apksigner list --name acme

# Show key details; optionally export the keystore + password to a directory.
apksigner get acme/release
apksigner get acme/release --out ./export

# Sign an APK. Signs straight from the local keystore; password never touches argv.
apksigner sign acme/release ./app-release-unsigned.apk --output ./app-release.apk

# Verify an APK signature (v1/v2/v3/v4 schemes).
apksigner verify ./app-release.apk

# Delete the key from the local repository AND the vault (-y skips the prompt).
apksigner delete acme/release -y
```

Notes:

- `generate --name <project> --alias <alias>`; if `--alias` is omitted a random
  six-character alias is generated.
- `sign`/`get`/`delete` accept either `name/alias` or a bare alias plus
  `--name <project>`.
- `get` prints the password to stdout — prefer `--out <dir>` when you need the
  files on disk (written `0600`).
- `--backend local` stores keys unencrypted on disk and is intended only for
  development/testing.

---

## Using from an AI agent (MCP)

Build with `--features mcp`, then register the binary as an MCP server over
stdio. The agent spawns the process and talks JSON-RPC to it.

```sh
cargo build --release --features mcp
# start the server (speaks MCP over stdin/stdout)
apksigner --config /path/to/config.toml serve
```

Example client configuration (JSON):

```json
{
  "mcpServers": {
    "apksigner": {
      "command": "/path/to/apksigner",
      "args": ["--config", "/path/to/config.toml", "serve"],
      "env": { "BW_SESSION": "<session token>" }
    }
  }
}
```

Tools exposed (parameter names are camelCase):

| Tool | Parameters | Description |
| --- | --- | --- |
| `generate_keystore` | `name?`, `alias?`, `validityDays?` | Generate a key; writes local + vault backup. |
| `list_keystores` | — | List keys in the local repository. |
| `sign_apk` | `apkPath`, `keyId`, `outputPath?` | Sign an APK from the local keystore (or vault). |
| `verify_apk` | `apkPath` | Verify an APK signature. |

The keystore password never leaves the process; tool results contain only the
signed APK path and verification status.

---

## Security notes

- `keytool` receives the password via a `0600` temp file; `apksigner` receives
  it via a child-only env var. Neither appears in the process list.
- Temp keystores and password files are written `0600` and overwritten with
  zeros before deletion.
- The `local` backend is **unencrypted** — use the Bitwarden backend for
  real release keys.
- `Bitwarden` encrypts client-side before upload; the self-hosted
  server only ever sees ciphertext.

---

## Building & CI

`cargo build --release --features mcp` produces the full binary (CLI + MCP).
The GitHub Actions workflow (`.github/workflows/release.yml`) builds release
artifacts for Linux x86_64, macOS arm64, and Windows x86_64 on every push to
`main`, and attaches them to a GitHub Release when a `v*` tag is pushed.

---

## License

MIT — see [LICENSE](LICENSE).
