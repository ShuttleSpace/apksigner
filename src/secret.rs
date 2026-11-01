//! Secret material handling: random password generation and helpers.
//!
//! Passwords are held in [`secrecy::SecretString`] so they are not inadvertently
//! printed, and they are zeroized on drop. When the password must briefly touch a
//! file or a child process, callers are responsible for deleting that material
//! immediately afterwards (see [`crate::util::secure_remove`]).

use secrecy::{ExposeSecret, SecretString};

/// Characters used for generated passwords.
///
/// We deliberately omit ambiguous glyphs (0/O, 1/l/I) so the value is easy to
/// transcribe and store in a vault without mistakes.
const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";

/// Default strength: 32 characters. Android store/key passwords have a 6 char
/// minimum; we generate far above that.
pub const DEFAULT_PASSWORD_LEN: usize = 32;

/// Generate a cryptographically random password of `len` characters.
///
/// The returned [`SecretString`] is zeroized when dropped.
pub fn generate_password(len: usize) -> SecretString {
    let len = len.max(6);
    let mut buf = String::with_capacity(len);
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        let idx = rand::Rng::gen_range(&mut rng, 0..ALPHABET.len());
        buf.push(ALPHABET[idx] as char);
    }
    SecretString::from(buf)
}

/// Helper to expose a secret as a byte slice for child-process env vars.
#[allow(dead_code)]
pub fn secret_bytes(secret: &SecretString) -> &[u8] {
    secret.expose_secret().as_bytes()
}
