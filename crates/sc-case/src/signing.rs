//! Signed evidence bundles: an Ed25519 signature over a bundle's
//! `MANIFEST.sha256`, and the check of it against the published keys.
//!
//! The manifest holds the SHA-256 of every other file, and `stamp.json`
//! names the case, so a valid signature over the manifest, with the manifest
//! check passing, shows that the whole bundle is as the holder of the
//! signing key wrote it. It says nothing about the email it came in.
//!
//! Three texts, all line-based:
//!
//! ```text
//! keys/bundle-signing.pub   ed25519 <public key, base64> <key id>   (one line per key)
//! MANIFEST.sha256.sig       algorithm: ed25519
//!                           key-id: <key id>
//!                           signature: <signature of MANIFEST.sha256's bytes, base64>
//! SWARMCHASE_SIGNING_KEY    the 32-byte secret seed, as 64 hex digits or base64
//! ```
//!
//! The key id is the first 16 hex digits of the SHA-256 of the 32 public key
//! bytes: what a recipient compares with the one the site publishes. The
//! signature is over the manifest's bytes as written, with no prefix, so any
//! Ed25519 implementation can check it. Lines starting with `#` are comments.
//!
//! No I/O: the caller reads the environment and the files. It compiles for
//! `wasm32-unknown-unknown`, where only the check is used.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;

/// The signature file's name, beside the manifest.
pub const SIGNATURE: &str = "MANIFEST.sha256.sig";
/// Where the published public keys are committed, as a repository path.
pub const PUBLIC_KEY_PATH: &str = "keys/bundle-signing.pub";
/// The environment variable that holds the secret seed.
pub const SECRET_ENV: &str = "SWARMCHASE_SIGNING_KEY";

/// A published signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// The first 16 hex digits of the SHA-256 of the key's 32 bytes.
    pub fn key_id(&self) -> String {
        crate::bundle::sha256_hex(self.0.as_bytes())[..16].to_string()
    }

    /// The key as base64 of its 32 bytes.
    pub fn base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }

    /// The key's line in a public key file.
    pub fn line(&self) -> String {
        format!("ed25519 {} {}", self.base64(), self.key_id())
    }
}

/// A public key file holding `keys`, with a comment saying what it is.
pub fn public_key_file(keys: &[PublicKey]) -> String {
    let mut s = String::from(
        "# The Ed25519 keys swarmchasing signs evidence bundles with (MANIFEST.sha256.sig).\n\
         # One per line: ed25519 <public key, base64> <key id>.\n",
    );
    for k in keys {
        s.push_str(&k.line());
        s.push('\n');
    }
    s
}

/// The keys in a public key file. A line whose key id does not match its
/// key is an error, so a mistyped key is caught where it is published.
pub fn parse_public_keys(text: &str) -> Result<Vec<PublicKey>, String> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let (Some("ed25519"), Some(b64)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "line {}: expected `ed25519 <base64> <key id>`",
                n + 1
            ));
        };
        let k = public_from_base64(b64).map_err(|e| format!("line {}: {e}", n + 1))?;
        if let Some(id) = parts.next()
            && id != k.key_id()
        {
            return Err(format!(
                "line {}: key id {id} does not match the key (its id is {})",
                n + 1,
                k.key_id()
            ));
        }
        keys.push(k);
    }
    if keys.is_empty() {
        return Err("no key in the file".into());
    }
    Ok(keys)
}

fn public_from_base64(b64: &str) -> Result<PublicKey, String> {
    let bytes: [u8; 32] = B64
        .decode(b64)
        .map_err(|e| format!("public key is not base64: {e}"))?
        .try_into()
        .map_err(|_| "a public key is 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map(PublicKey)
        .map_err(|_| "not an Ed25519 public key".to_string())
}

/// The secret signing key. It has no `Debug` or `Display`, so it cannot be
/// printed by accident.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// The key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The key from `SWARMCHASE_SIGNING_KEY`'s value: 64 hex digits or the
    /// base64 of 32 bytes. Errors never quote the value.
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.trim();
        let seed: Vec<u8> = if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
            (0..32)
                .map(|i| u8::from_str_radix(&v[2 * i..2 * i + 2], 16).unwrap_or(0))
                .collect()
        } else {
            B64.decode(v).map_err(|_| {
                format!("{SECRET_ENV}: expected 64 hex digits or base64 of 32 bytes")
            })?
        };
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| format!("{SECRET_ENV}: the seed is 32 bytes"))?;
        Ok(Self::from_seed(&seed))
    }

    /// The seed as 64 hex digits, for the file `swarmchase key generate`
    /// writes. Never print it.
    pub fn seed_hex(&self) -> String {
        self.0
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// The signature file for `manifest`.
    pub fn sign_manifest(&self, manifest: &str) -> String {
        let sig = self.0.sign(manifest.as_bytes());
        format!(
            "# Ed25519 signature of MANIFEST.sha256 by swarmchasing bundle key {id}.\n\
             algorithm: ed25519\n\
             key-id: {id}\n\
             signature: {}\n",
            B64.encode(sig.to_bytes()),
            id = self.public().key_id(),
        )
    }
}

/// What a signature check found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureCheck {
    /// No signature file.
    Unsigned,
    /// Valid, by a published key.
    Signed { key_id: String },
    /// Present, but no published key to check it against.
    Unchecked { key_id: String },
    /// Malformed, by a key that is not published, or not valid for this
    /// manifest.
    Invalid {
        key_id: Option<String>,
        reason: String,
    },
}

impl SignatureCheck {
    /// Whether the bundle fails its check because of the signature.
    pub fn fails(&self) -> bool {
        matches!(self, Self::Invalid { .. })
    }

    /// One line for the CLI.
    pub fn line(&self) -> String {
        match self {
            Self::Unsigned => format!("unsigned: no {SIGNATURE}"),
            Self::Signed { key_id } => format!("signed by key {key_id}"),
            Self::Unchecked { key_id } => format!(
                "signature by key {key_id} not checked: no published key to check it against"
            ),
            Self::Invalid { reason, .. } => format!("signature invalid: {reason}"),
        }
    }
}

/// Check `signature` (the text of [`SIGNATURE`], `None` when the bundle has
/// none) over `manifest` against the `published` keys.
pub fn check(manifest: &str, signature: Option<&str>, published: &[PublicKey]) -> SignatureCheck {
    let Some(text) = signature else {
        return SignatureCheck::Unsigned;
    };
    let invalid = |key_id: Option<&str>, reason: &str| SignatureCheck::Invalid {
        key_id: key_id.map(str::to_string),
        reason: reason.to_string(),
    };
    let field = |name: &str| {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == name))
            .map(|(_, v)| v.trim())
    };
    let key_id = field("key-id").filter(|v| !v.is_empty());
    if field("algorithm") != Some("ed25519") {
        return invalid(key_id, "not an ed25519 signature file");
    }
    let Some(key_id) = key_id else {
        return invalid(None, "no key-id");
    };
    let sig = match field("signature").map(|s| B64.decode(s)) {
        Some(Ok(b)) => match <[u8; 64]>::try_from(b) {
            Ok(b) => Signature::from_bytes(&b),
            Err(_) => return invalid(Some(key_id), "a signature is 64 bytes"),
        },
        _ => return invalid(Some(key_id), "no base64 signature"),
    };
    if published.is_empty() {
        return SignatureCheck::Unchecked {
            key_id: key_id.to_string(),
        };
    }
    let Some(key) = published.iter().find(|k| k.key_id() == key_id) else {
        return invalid(
            Some(key_id),
            &format!(
                "made with key {key_id}, which is not a published key ({})",
                published
                    .iter()
                    .map(PublicKey::key_id)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    };
    match key.0.verify_strict(manifest.as_bytes(), &sig) {
        Ok(()) => SignatureCheck::Signed {
            key_id: key_id.to_string(),
        },
        Err(_) => invalid(
            Some(key_id),
            &format!("does not match MANIFEST.sha256 under key {key_id}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "aa  records.ndjson\nbb  analysis.json\ncc  stamp.json\n";

    fn key(n: u8) -> SecretKey {
        SecretKey::from_seed(&[n; 32])
    }

    #[test]
    fn a_signature_verifies_under_its_published_key() {
        let k = key(7);
        let sig = k.sign_manifest(MANIFEST);
        let published =
            parse_public_keys(&public_key_file(&[key(1).public(), k.public()])).unwrap();
        assert_eq!(published.len(), 2);
        let c = check(MANIFEST, Some(&sig), &published);
        assert_eq!(
            c,
            SignatureCheck::Signed {
                key_id: k.public().key_id()
            }
        );
        assert_eq!(c.line(), format!("signed by key {}", k.public().key_id()));
        assert!(!c.fails());
        assert_eq!(k.public().key_id().len(), 16);
    }

    #[test]
    fn tampering_a_wrong_key_and_no_signature_show() {
        let k = key(7);
        let sig = k.sign_manifest(MANIFEST);
        let published = [k.public()];
        // One hash in the manifest changed: the signature no longer holds.
        let tampered = MANIFEST.replace("bb", "bc");
        let c = check(&tampered, Some(&sig), &published);
        assert!(c.fails(), "{c:?}");
        assert!(c.line().contains("does not match MANIFEST.sha256"));
        // A signature by someone else's key, claiming our key id or its own.
        let forged = key(9).sign_manifest(MANIFEST);
        assert!(check(MANIFEST, Some(&forged), &published).fails());
        let relabelled = forged.replace(&key(9).public().key_id(), &k.public().key_id());
        let c = check(MANIFEST, Some(&relabelled), &published);
        assert!(c.line().contains("does not match"), "{c:?}");
        // An altered signature, a missing field, nothing at all.
        let flipped = sig.replace("signature: ", "signature: AA");
        assert!(check(MANIFEST, Some(&flipped), &published).fails());
        let no_alg = sig.replace("algorithm: ed25519\n", "");
        assert!(check(MANIFEST, Some(&no_alg), &published).fails());
        assert_eq!(check(MANIFEST, None, &published), SignatureCheck::Unsigned);
        assert!(!SignatureCheck::Unsigned.fails());
        // No published key: present but not checked, never "signed".
        assert!(matches!(
            check(MANIFEST, Some(&sig), &[]),
            SignatureCheck::Unchecked { .. }
        ));
    }

    // RFC 8032 section 7.1, test 1: the signature is plain Ed25519 over the
    // manifest's bytes, so any implementation can check it.
    #[test]
    fn signs_as_rfc_8032_does() {
        let k =
            SecretKey::parse("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&B64.decode(k.public().base64()).unwrap()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = k.sign_manifest("");
        let b64 = sig
            .lines()
            .find_map(|l| l.strip_prefix("signature: "))
            .unwrap();
        assert_eq!(
            hex(&B64.decode(b64).unwrap()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn secrets_and_key_files_parse() {
        let k = key(3);
        let hex = k.seed_hex();
        assert_eq!(hex.len(), 64);
        let b64 = B64.encode([3u8; 32]);
        for v in [
            hex.as_str(),
            &hex.to_uppercase(),
            &b64,
            &format!(" {hex}\n"),
        ] {
            assert_eq!(SecretKey::parse(v).unwrap().public(), k.public());
        }
        for bad in ["", "abc", &hex[..62], &B64.encode([0u8; 31])] {
            let e = SecretKey::parse(bad).err().unwrap();
            assert!(e.starts_with(SECRET_ENV) && !e.contains(&hex), "{e}");
        }
        let line = k.public().line();
        assert!(parse_public_keys(&line).is_ok());
        let wrong_id = format!("{} 0000000000000000", &line[..line.rfind(' ').unwrap()]);
        assert!(
            parse_public_keys(&wrong_id)
                .unwrap_err()
                .contains("does not match")
        );
        assert!(parse_public_keys("# only a comment\n").is_err());
        assert!(parse_public_keys("rsa AAAA").is_err());
        assert!(parse_public_keys("ed25519 AAAA").is_err());
    }
}
